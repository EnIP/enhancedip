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
	fprintf(stderr, "**************************************\n");
	fprintf(stderr, "*                                    *\n");
	fprintf(stderr, "*     TCP connect port scanner       *\n");
	fprintf(stderr, "*     1st connect without IP options *\n");
	fprintf(stderr, "*     2nd connect with IP options    *\n");
	fprintf(stderr, "*     results printed as 0's and 1's *\n");
	fprintf(stderr, "*                                    *\n");
	fprintf(stderr, "**************************************\n");
	fprintf(stderr, "\n\n");
	fprintf(stderr, "Example:\n");
	fprintf(stderr, "%s <ipaddr> <portnumber>\n", progname);
	fprintf(stderr, "%s <ipaddr>/<netmask> <portnumber>\n", progname);
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
    char *netmask = NULL;

    if (argc < 3) {
       usage(argv[0]);
       exit(0);
    }

    ipaddress = argv[1];
    portno    = argv[2];
    netmask   = index(ipaddress, '/');
    
    if(argc == 4)
       verbose   = atoi(argv[3]);

    if(netmask == NULL){
    	retval1 = do_connect(ipaddress, portno, WITHOUT_OPTIONS);
    	if(retval1 > 0){
    		retval2 = do_connect(ipaddress, portno, WITH_OPTIONS);
    	}

    	printf("%s %s %d %d\n", ipaddress, portno, retval1, retval2); 
    }
    else{
        *netmask  = '\0'; netmask++;

	process_netmask(ipaddress, portno, netmask);	
    }

    return 0;

 }

int process_netmask(char *ipaddr, char *portno, char *netmask)
 {
   int nm = 0;
   int hostbits = 0;
   double hostcount = 0;
   unsigned int ipaddress = 0;
   int x = 0;
   struct in_addr addr;
   char *ip_address = NULL;
   int retval1 = 0;
   int retval2 = 0;

   nm         = atoi(netmask);
   ipaddress  = ntohl(inet_addr(ipaddr));

   if(nm <= 0 || nm > 32){
	fprintf(stderr, "Error: 0 >= netmask >= 32\n");
	return 0;
   }

   hostbits  = 32 - nm;
   hostcount = pow(2, hostbits);

   //iterate through all the ip addresses
   for(x=0;x<hostcount;x++){
	addr.s_addr = htonl(ipaddress+x);
	ip_address = inet_ntoa(addr);

	retval1 = do_connect(ip_address, portno, WITHOUT_OPTIONS);
	if(retval1 > 0){
	   retval2 = do_connect(ip_address, portno, WITH_OPTIONS);
	}
	
	printf("%s %s %d %d\n", ip_address, portno, retval1, retval2);

	if(retval1 == 1 && retval2 == 1){
		break;
	}
   }

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
   char opt[12] = {0};
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
	return 0;
      }
   } 

   fcntl(sockfd, F_SETFL, O_NONBLOCK);
   rv = connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr));
   if(rv == -1 && errno == ENETUNREACH){
   	if(verbose){
          fprintf(stderr, "%s : network unreachable\n", connect_str);
	}
   	close(sockfd);
	return 0;
   }

   FD_ZERO(&fdset);
   FD_SET(sockfd, &fdset);
   tv.tv_sec = 5;  
   tv.tv_usec = 0; //1/4 of a second

   if(select(sockfd+1, NULL, &fdset, NULL, &tv) == 1){
	int so_error;
	socklen_t len = sizeof(so_error);

	getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
	if(so_error == 0){
	   retval = 1;
	}
	else{
	   retval = 0;
	   if(verbose){
	     perror("getsockopt");
	     fprintf(stderr, "%s : failed with error code %d\n", 
	              connect_str, so_error);
	   }
	}
   }
   else{
	retval = 0;
	if(verbose){
	   fprintf(stderr, "%s : socket timeout\n", connect_str, portno);
	}
   }

   close(sockfd);

   return retval;
}

