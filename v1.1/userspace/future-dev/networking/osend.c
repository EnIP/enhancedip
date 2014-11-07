#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <arpa/inet.h>
#include <errno.h>

#pragma pack(1)

#define WITHOUT_OPTIONS 0
#define WITH_OPTIONS 1

int verbose = 0;

int process_netmask(char *, char *, char *);
int do_connect(char *, char *, int);
void error(const char *);
void usage(char *);

void usage(char *progname)
{
	fprintf(stderr, "\n");
	fprintf(stderr, "Example:\n");
	fprintf(stderr, "%s <ipaddr> <portnumber> <filename>\n", progname);
	fprintf(stderr, "\n\n");
}

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char *argv[])
{
    int retval1 = 0;
    int retval2 = 0;
    char *ipaddress = NULL;
    char *portno = NULL;
    char *filename = NULL;
    int sockfd = 0;
    struct stat sb;
    char buf[8192] = {0};
    fd_set writefds;
    ssize_t readlen = 0;
    ssize_t writelen = 0;
    ssize_t fileoffset = 0;
    int fd = 0;

    if (argc < 4) {
       usage(argv[0]);
       exit(0);
    }

    ipaddress = argv[1];
    portno    = argv[2];
    filename  = argv[3];

    sockfd = do_connect(ipaddress, portno, WITH_OPTIONS);
    if(sockfd < 0){
	fprintf(stderr, "connect");
	exit(-1);
    }

    fd = open(filename, O_RDONLY);
    if(fd < 0){
	perror("open");
	exit(-1);
    }

    if(fstat(fd, &sb) != 0){
	perror("stat");
	goto cleanup;
    }

    while(1){
	///read data from file
	readlen = read(fd, buf, sizeof(buf));
	if(readlen == 0){
		fprintf(stderr, "eof\n");
		break;
	}
	else if(readlen < 0){
		perror("read");
		break;
	}
	fileoffset += readlen;

	///write data out socket
    	FD_ZERO(&writefds);
	FD_SET(sockfd, &writefds);
    	retval1 = select(sockfd+1, NULL, &writefds, NULL, NULL);
	if(retval1 != 1){
		perror("select");
		break;
	}

	writelen = write(sockfd, buf, readlen);
	if(writelen != readlen){
		perror("write");
		break;
	}
    }

cleanup:
    if(sockfd > 0){ close(sockfd); }
    if(fd>0){ close(fd); }


    return 0;

 }


/**
 * Make a TCP connection to ipaddr, port
 * if with_opts = 1, then add 12 bytes of zero-filled IP options
 * to each packet.  Return 1 if connect is successful, return 0 if not
 */
 int do_connect(char *ipaddr, char *portno, int with_opts)
 {
   struct timeval tv;
   fd_set fdset;
   int portnum = 0;
   int sockfd = 0;
   int retval = 0;
   int rv = 0;
   //char opt[12] = {0};
   char opt[12] = "\x9a\x0c\x03\x00\x0a\x01\x01\x02\x0a\x03\x03\x02";
   struct sockaddr_in serv_addr;
   char connect_str[1024] = {0};

   snprintf(connect_str, 1024, "connect(%s, %s, %d)", 
   					ipaddr, portno, with_opts); 

   portnum = atoi(portno);
   sockfd  = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 0) 
        error("ERROR opening socket");

   serv_addr.sin_family= AF_INET;
   serv_addr.sin_port = htons(portnum);
   serv_addr.sin_addr.s_addr=inet_addr(ipaddr);

   if(with_opts > 0){
      retval = setsockopt(sockfd, IPPROTO_IP, IP_OPTIONS, opt, sizeof(opt));
      if(retval == -1){
      	if(verbose){ 
	   fprintf(stderr, "%s : setsockopt IP_OPTIONS failed\n", connect_str); 
	}
        close(sockfd);
	perror("setsockopt");
	return -1;
      }
   } 

   fcntl(sockfd, F_SETFL, O_NONBLOCK);
   rv = connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr));
   if(rv == -1 && errno == ENETUNREACH){
   	if(verbose){
          fprintf(stderr, "%s : network unreachable\n", connect_str);
	}
   	close(sockfd);
	return -2;
   }

   FD_ZERO(&fdset);
   FD_SET(sockfd, &fdset);
   tv.tv_sec = 5;  
   tv.tv_usec = 0; //1/4 of a second

   if(select(sockfd+1, NULL, &fdset, NULL, &tv) == 1){
	int so_error;
	socklen_t len = sizeof(so_error);

	getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
	if(so_error != 0){
	   retval = -2;
	   if(verbose){
	     perror("getsockopt");
	     fprintf(stderr, "%s : failed with error code %d\n", 
	              connect_str, so_error);
	   }
	   close(sockfd);
	   return retval;
	}
   }
   else{
	retval = -3;
	if(verbose){
	   fprintf(stderr, "%s : socket timeout\n", connect_str, portno);
	}
	close(sockfd);
	return retval;
   }

   return sockfd;
}

