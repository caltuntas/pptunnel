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

char *remote_host;
char *remote_port;

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
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
    if (new_fd == -1) {
      perror("accept");
      continue;
    }

    inet_ntop(their_addr.ss_family,get_in_addr((struct sockaddr *)&their_addr),s, sizeof s);
    printf("server: got connection from...%s\n", s);




//pid_t pid= fork();

//    if (pid == 0) {
      close(sockfd);
      remote_fd = create_remote_connection();
      forward_data(new_fd,remote_fd);
      close(new_fd);
      exit(0);
//    }

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
