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

#include "eip.h"

struct ipopt
{
    	unsigned char copied:1;
	unsigned char class:2;
	unsigned char number:5;
	unsigned char length;
	unsigned char data[2];
};

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

/*
struct sockaddr_ein{
	unsigned short sin_family;
	unsigned short sin_port;
	in_addr_t sin_addr1;
	in_addr_t sin_addr2;
	char __pad[14];
};
*/

int main(int argc, char *argv[])
{
    int sockfd, portno, n;
    size_t counter = 0;
    struct sockaddr_ein serv_addr;
    struct hostent *server1;
    struct hostent *server2;
    char *options = NULL;
    int retval = 0;
    struct ipopt opt;
    char buffer[100000];

    if (argc < 5) {
       fprintf(stderr,"usage %s sitename hostname port [udp|tcp]\n", argv[0]);
       exit(0);
    }

    portno = atoi(argv[3]);

    if(strcmp(argv[4], "tcp")==0){
       	sockfd = socket(AF_INET, SOCK_STREAM, 0);
    }
    else if(strcmp(argv[4], "udp")==0){
    	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    }
    else{
	error("tcp|udp\n");
    }
    
    if (sockfd < 0) 
        error("ERROR opening socket");

   memset(&serv_addr, 0, sizeof(struct sockaddr_ein));
   serv_addr.sin_family= AF_INET;
   serv_addr.sin_port = htons(portno);
   serv_addr.sin_addr1=inet_addr(argv[1]);
   serv_addr.sin_addr2=inet_addr(argv[2]);

   if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

    //fgets(buffer, 1000, stdin);
    //I did this to see some ASCII text
    bzero(buffer,100000);
    memcpy(buffer, "GET ", 4);
    n=4;
    n = write(sockfd,buffer,n);
    if (n < 0) 
        error("ERROR writing to socket");

    while(1){
       bzero(buffer,65535);
       n = read(sockfd,buffer,65535);
       if(n == 0 ){ 
       	    fprintf(stderr, "eof.  counter=%ld\n",counter); 
	    break; 
       }
       else if(n < 0){ 
           perror("read"); 
	   fprintf(stderr, "counter=%ld\n", counter);
	   break; 
       }
       else{ 
          counter += n;
	  write(1, buffer, n);
       }

    }
    close(sockfd);

    return 0;
}
