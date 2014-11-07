#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>

#define MAX_MSG_SIZE 65536/2

int main(int argc, char **argv)
{
   int sockfd;
   int retval;
   int portno;
   int yes;
   struct sockaddr_in my_addr, client_addr;
   int cliLen = sizeof(client_addr);
   char data[MAX_MSG_SIZE] = {0};
   ssize_t byte_counter = 0;

   if(argc < 3){
	printf("%s [file] [portno]\n", argv[0]);
	exit(0);
   }

   portno = atoi(argv[2]);

   bzero(&my_addr,sizeof(my_addr));
   bzero(&client_addr,sizeof(client_addr));

   sockfd = socket(AF_INET,SOCK_DGRAM,0);
   if(sockfd < 0){
	perror("socket");
	exit(-1);
   }

   //print error if sockfd is NULL
   yes=1;
   setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) ;

   //
   ////Fill the socket details
   my_addr.sin_family = AF_INET ;      /* host byte order*/
   my_addr.sin_port = htons(portno) ;  /* short, network byte order*/
   my_addr.sin_addr.s_addr = htonl(INADDR_ANY) ; /*automatically fill with IP*/

   memset(&my_addr.sin_zero, 0, 8); /* zero the rest of the struct*/

   if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1)
   {
   	perror("Bind");
	exit(-1);
   }

   int fd = 0;
   int y = 0;

   fd = open(argv[1], O_RDONLY);
   if(fd<0){
   	perror("open");
	exit(-12);
   }

   memset(data, 0, MAX_MSG_SIZE);
   retval = recvfrom(sockfd, data, MAX_MSG_SIZE, 0,
   		(struct sockaddr *) &client_addr, &cliLen) ;
	    if(retval == -1){
		perror("recvfrom");
		exit(-2);
	    }
   printf("%s\n", data); fflush(stdout);

   while (1)
   {
	y = read(fd, data, MAX_MSG_SIZE);
	if(y > 0){
	   byte_counter += y;

   	   retval = sendto(sockfd, data, y, 0, 
			(struct sockaddr*) &client_addr, cliLen) ; 
   	   if (retval != y){
		printf("retval=%d len(data)=%d\n", retval, y);
		perror("sendto");
		exit(-45);
	   }
	   usleep(1000*10);
	}
	else if(y==0){
		fprintf(stderr, "bytecounter = %ld\n", byte_counter);
		fprintf(stderr, "exit eof\n");
		fflush(stderr);
		exit(0);
	}
	else{
		perror("read");
		exit(-123);
	}
	//printf("."); fflush(stdout);
    } 
	
}
