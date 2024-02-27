#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#define PORT "3490"
#define BACKLOG 10
#define BUF_SIZE 16
#define BROKEN_PIPE_ERROR -9

#define V2_VERSION 0x2
#define V2_CMD_LOCAL 0x0
#define V2_CMD_PROXY 0x1
#define V2_AF_INET 0x1
#define V2_TRANSPORT_STREAM 0x1

char *remote_host;
char *remote_port;
struct header {
  struct proxy_hdr_v2 {
    uint8_t sig[12];
    uint8_t ver_cmd;
    uint8_t fam;    
    uint16_t len;   
  } hdr_v2;
  uint32_t src;
  uint32_t dst;
  uint16_t src_port;
  uint16_t dst_port;
};
uint8_t * serialize_header(uint8_t *buffer, struct header *hdr) ;
int create_remote_connection();
void forward_data(int source_sock, int destination_sock);
void sigchld_handler(int s) {
  int saved_errno = errno;

  while(waitpid(-1, NULL, WNOHANG) > 0);

  errno = saved_errno;
}

void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void init_hdr_v2(struct header *hdr) {
  hdr->hdr_v2.sig[0] = 0x0D;
  hdr->hdr_v2.sig[1] = 0x0A;
  hdr->hdr_v2.sig[2] = 0x0D;
  hdr->hdr_v2.sig[3] = 0x0A;
  hdr->hdr_v2.sig[4] = 0x00;
  hdr->hdr_v2.sig[5] = 0x0D;
  hdr->hdr_v2.sig[6] = 0x0A;
  hdr->hdr_v2.sig[7] = 0x51;
  hdr->hdr_v2.sig[8] = 0x55;
  hdr->hdr_v2.sig[9] = 0x49;
  hdr->hdr_v2.sig[10] = 0x54;
  hdr->hdr_v2.sig[11] = 0x0A;

  hdr->hdr_v2.ver_cmd = (V2_VERSION << 4) | V2_CMD_PROXY;
  hdr->hdr_v2.fam = (V2_AF_INET << 4) | V2_TRANSPORT_STREAM;
  hdr->hdr_v2.len = 12;
}

int main(int argc, char *argv[]){
  int sockfd, new_fd, remote_fd;
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_storage their_addr;
  socklen_t sin_size;
  struct sigaction sa;
  int yes=1;
  char s[INET_ADDRSTRLEN];
  int rv;

  if (argc !=3 ) {
    fprintf(stderr, "usage: client hostname\n");
    remote_host = "localhost";
    remote_port = "5000";
  } else {
    remote_host = argv[1];
    remote_port = argv[2];
  }


  memset(&hints, 0 , sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) !=0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  for (p = servinfo; p!=NULL; p=p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("server:socket");
      continue;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))==-1) {
      perror("setsockopt");
      exit(1);
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("server:bind");
      continue;
    }

    break;
  }

  freeaddrinfo(servinfo);

  if (p == NULL) {
    fprintf(stderr, "server: failed to bind\n");
    exit(1);
  }

  if (listen(sockfd, BACKLOG) == -1) {
    perror("listen");
    exit(1);
  }

  sa.sa_handler = sigchld_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction");
    exit(1);
  }

  printf("server: waiting for connections...\n");

  while(1) {
    sin_size = sizeof their_addr;
    struct sockaddr *addr = (struct sockaddr *)&their_addr;
    new_fd = accept(sockfd, addr, &sin_size);
    if (new_fd == -1) {
      perror("accept");
      continue;
    }
    void *in_addr = get_in_addr(addr);
    struct in_addr *s_addr = (struct in_addr *)in_addr;
    inet_ntop(their_addr.ss_family,in_addr,s, sizeof s);
    printf("server: got connection from...%s\n", s);




    close(sockfd);
    remote_fd = create_remote_connection();
    struct header hdr;
    memset(&hdr,0, sizeof hdr);
    //hdr.src = s_addr->s_addr;
    unsigned char buf[sizeof(struct in_addr)];
    struct sockaddr_in sa_src;
    struct sockaddr_in sa_dst;
    inet_pton(AF_INET, "192.168.100.101", &(sa_src.sin_addr));
    inet_pton(AF_INET, "192.168.100.105", &(sa_dst.sin_addr));
    hdr.src = sa_src.sin_addr.s_addr;
    hdr.dst = sa_dst.sin_addr.s_addr;
    hdr.src_port = 1234;
    hdr.dst_port = 4567;

    uint8_t buffer[28], *ptr;
    init_hdr_v2(&hdr);

    ptr = serialize_header(buffer, &hdr);

    ssize_t n = send(remote_fd, buffer, sizeof(buffer), 0); // send data to output socket
    if (n == -1 ) 
      perror("send");
    forward_data(new_fd,remote_fd);
    close(new_fd);
    exit(0);

    close(new_fd);
  }


  return 0;
}

void forward_data(int source_sock, int destination_sock) {
  ssize_t n;
  ssize_t nsend;
  char buffer[BUF_SIZE];

  while ((n = recv(source_sock, buffer, BUF_SIZE, 0)) > 0) { // read data from input socket
    nsend = send(destination_sock, buffer, n, 0); // send data to output socket
    if (nsend == -1 ) 
      perror("send");
  }

  if (n < 0) {
    exit(BROKEN_PIPE_ERROR);
  }
  shutdown(destination_sock, SHUT_RDWR); // stop other processes from using socket
  close(destination_sock);

  shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
  close(source_sock);
}

int create_remote_connection() {
  int sockfd, numbytes;
  struct addrinfo hints, *servinfo, *p;
  int rv;
  char s[INET6_ADDRSTRLEN];

  memset(&hints,0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((rv = getaddrinfo(remote_host, remote_port, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }


  for (p= servinfo; p!=NULL; p=p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }

    if (connect(sockfd, p->ai_addr, p->ai_addrlen)==-1){
      close(sockfd);
      perror("client: connect");
      continue;
    }

    break;
  }

  if (p==NULL) {
    fprintf(stderr, "client: failed to connect\n");
    return 2;
  }

  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),s,sizeof s);
  printf("client: connecting to %s\n",s);

  freeaddrinfo(servinfo);

  return sockfd;
}

uint8_t * serialize_header(uint8_t *buffer, struct header *hdr) 
{
  memcpy(buffer, hdr->hdr_v2.sig,sizeof(hdr->hdr_v2.sig));
  buffer[12] = hdr->hdr_v2.ver_cmd;
  buffer[13] = hdr->hdr_v2.fam;
  uint16_t len = htons(hdr->hdr_v2.len);
  buffer[14] = (uint8_t)len;
  buffer[15] = (uint8_t)(len>>=8);
  uint32_t src = hdr->src;
  buffer[16] = (uint8_t)src;
  buffer[17] = (uint8_t)(src>>=8);
  buffer[18] = (uint8_t)(src>>=8);
  buffer[19] = (uint8_t)(src>>=8);
  uint32_t dst = hdr->dst;
  buffer[20] = (uint8_t)dst;
  buffer[21] = (uint8_t)(dst>>=8);
  buffer[22] = (uint8_t)(dst>>=8);
  buffer[23] = (uint8_t)(dst>>=8);
  uint16_t src_port = htons(hdr->src_port);
  buffer[24] = (uint8_t)src_port;
  buffer[25] = (uint8_t)(src_port>>=8);
  uint16_t dst_port = htons(hdr->dst_port);
  buffer[26] = (uint8_t)dst_port;
  buffer[27] = (uint8_t)(dst_port>>=8);
  return buffer;
}

