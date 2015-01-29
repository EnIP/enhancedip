#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#pragma pack(1)

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char *argv[])
{
    int sockfd, portno, n;
    size_t counter = 0;
    struct sockaddr_in serv_addr;
    struct hostent *server1;
    struct hostent *server2;
    char *options = NULL;
    int retval = 0;
    char buffer[100000];
    char opt[12] = {0};
    //char opt[12] = "\x9a\x0c\x03\x00\x0a\x01\x01\x02\x0a\x03\x03\x02";

    int with_options = 0;

    if (argc < 4) {
       fprintf(stderr,"usage: %s ipaddr port 0|1\n", argv[0]);
       exit(0);
    }
    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    //sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

   serv_addr.sin_family= AF_INET;
   serv_addr.sin_port = htons(portno);
   serv_addr.sin_addr.s_addr=inet_addr(argv[1]);

   if(strncmp(argv[3], "1", 1) == 0){
	with_options = 1;
   }

   if(with_options == 1){
      retval = setsockopt(sockfd, IPPROTO_IP, IP_OPTIONS, opt, 12);
      if(retval == -1){
	perror("setsockopt");
	return -1;
      }
   }

   if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

    bzero(buffer,100000);
    memcpy(buffer, "GET /\r\n", 7);
	
    //printf("strlen=%d\n", strlen(buffer)); fflush(stdout);

    n = write(sockfd,buffer,strlen(buffer));
    if (n < 0) 
         error("ERROR writing to socket");

    while(1){
       bzero(buffer,100000);
       n = read(sockfd,buffer,1);
       if(n == 0 ){ 
       	    fprintf(stderr, "eof.  counter=%ld\n",(long int)counter); 
	    break; 
       }
       else if(n < 0){ 
           perror("read"); 
	   fprintf(stderr, "counter=%ld\n", (long int)counter);
	   break; 
       }
       else{ 
          counter += n;
       	  printf("%s",buffer);
	  fflush(stdout);
       }
    }
    close(sockfd);

    return 0;
}
