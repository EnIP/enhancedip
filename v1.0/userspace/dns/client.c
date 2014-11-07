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

#define DNS_SERVER "10.70.7.4"
#define DNS_PORTNO (53)
#define BUFSIZE 8192

char dns_query[] = "\x74\x77"
		   "\x01\x00"
		   "\x00\x01"
		   "\x00\x00"
		   "\x00\x00"
		   "\x00\x00"
		   "\x04\x69\x70\x76\x36"
		   "\x06\x67\x6f\x6f\x67\x6c\x65"
		   "\x03\x63\x6f\x6d\x00"
		   "\x00\x1c"
		   "\x00\x01";

int expand_hostname(char *hn, char **ehn, int *ehn_len)
{
	int x = 0;
	int xx = 0;
	int y = 0;
	int lp = 0;
	int po[256] = {0}; //po = period offsets

	char *p = calloc(1, 2048);
	if(!p){ return -1; }

}


void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int parse_dns_reply(char *buf, int len)
{


}

int main(int argc, char *argv[])
{
    int sockfd, n;
    size_t counter = 0;
    struct sockaddr_in serv_addr;
    struct hostent *server1;
    struct hostent *server2;
    int retval = 0;
    char buffer[BUFSIZE];
    char *hostname = NULL;

    if (argc < 2) {
       fprintf(stderr,"usage %s hostname\n", argv[0]);
       exit(0);
    }

    hostname = argv[1];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

   serv_addr.sin_family= AF_INET;
   serv_addr.sin_port = htons(DNS_PORTNO);
   serv_addr.sin_addr.s_addr=inet_addr(DNS_SERVER);

   if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

    memset(buffer,0, BUFSIZE);
    memcpy(buffer, dns_query, 33); n=33;
    //n=construct_dns_query(buffer, BUFSIZE, hostname); 
    //if(n < 0){
//	goto cleanup;
 //   }

    n = write(sockfd,buffer,n);
    if (n < 0) 
         error("ERROR writing to socket");

    memset(buffer,0, BUFSIZE);
    n = read(sockfd,buffer,BUFSIZE);
    if(n == 0 ){ 
       //fprintf(stderr, "eof.  counter=%ld\n",counter); 
	goto cleanup;
    }
    else if(n < 0){
	error("read");
    }

    parse_dns_reply(buffer, n);

cleanup:
    close(sockfd);

    return 0;
}
