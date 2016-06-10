/*
 *    pinger.c 
 *    This is a ping imitation program 
 *    It will send an ICMP ECHO packet to the server of 
 *    your choice and listen for an ICMP REPLY packet
 *    Have fun!
 */
/*
 *    pinger.c 
 *    This is a ping imitation program 
 *    It will send an ICMP ECHO packet to the server of 
 *    your choice and listen for an ICMP REPLY packet
 *    Have fun!
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <unistd.h>
#include "hexdump.h"
#include "mytypes.h"
#include "oping.h"

unsigned short in_cksum(unsigned short *, int);
void parse_argvs(int, char**, struct in_addr *, struct in_addr *, struct in_addr *, 
		int *, int *, useconds_t *, int *);
void usage();
char* getip();

/**
	Choose a 4 byte value at random for use as an IP address.
	Filter out the random value if it is in our list of bad
	addresses.

*/
unsigned int findip()
{
	unsigned int randomip = 0;
	struct in_addr badip1;
	struct in_addr badip2;
	struct in_addr badip3;
	struct in_addr badip4;
	struct in_addr badip5;
	struct in_addr badip6;
	
	inet_aton("127.0.0.0", &badip1);
	inet_aton("240.0.0.0", &badip2);
	inet_aton("192.168.0.0", &badip3);
	inet_aton("10.0.0.0", &badip4);
	inet_aton("172.16.0.0", &badip5);
	inet_aton("169.254.0.0", &badip6);

	do{
	   randomip = (unsigned int)random();

	   if(randomip&0xFF000000 == badip1.s_addr){
		randomip=0;
	   }
           else if(randomip&0xFF000000 == badip2.s_addr){
		randomip=0;
	   }
	   else if(randomip&0xFFFF0000 == badip3.s_addr){
		randomip=0;
	   }
	   else if(randomip&0xFF000000 == badip4.s_addr){
		randomip=0;
	   }
	   else if(randomip&0xFFFF0000 == badip5.s_addr){
		randomip=0;
	   }
	   else if(randomip&0xFFFF0000 == badip6.s_addr){
		randomip=0;
	   }

	}while(randomip == 0);

	return randomip;
}

int main(int argc, char* argv[])
{
    int x = 0;
    int retval = 0;
    int counter = 0;
    struct in_addr src_addr;
    struct in_addr dst_addr;
    struct in_addr extended_src;
    struct in_addr extended_dst;
    int both = 0;    //if set to 1 alternates between 
    		     //regular ping (rping) and IP options ping (oping) 
    unsigned int ctr = 0;  
    int use_counter = 0;
    useconds_t sleep_amount = 1000000;
    int64 difference = 0;
    int rand_init = 0;
    unsigned int randomip = 0;

    if (getuid() != 0)
    {
	fprintf(stderr, "%s: root privelidges needed\n", *(argv + 0));
	exit(EXIT_FAILURE);
    }

    parse_argvs(argc, argv, &src_addr, 
    		&extended_src, &extended_dst, &both, &counter, &sleep_amount, &rand_init);

    fprintf(stderr, "Source address: %s\n", inet_ntoa(src_addr));
    fprintf(stderr, "Destination address: %s\n", inet_ntoa(dst_addr));

    if(counter > 0){
	use_counter = 1;
    }

    //init the random num generator
    if(rand_init){ srandom(rand_init); }
    else{ srandom(time(NULL)); }

    while(1){
	randomip = findip();
	dst_addr.s_addr = htonl(randomip);
	retval = rping(dst_addr, src_addr, &difference);
	printf("rping retval = %d, difference=%lld\n", retval, difference);
	exit(0);
    }

    while(1)
    {
        if(both && ctr%2==0){
           retval = rping(dst_addr, src_addr, &difference);	
           if(retval < 0){
	      fprintf(stderr, "oping failure\n");
	      exit(EXIT_FAILURE);
           }
	   printf("Received rping %s,%lld\n", inet_ntoa(dst_addr), difference);
	}
	else{
           retval = oping(dst_addr, src_addr, extended_src, extended_dst, &difference);	
           if(retval < 0){
	      fprintf(stderr, "oping failure\n");
	      exit(EXIT_FAILURE);
           }
	   printf("Received oping %s,%lld\n", inet_ntoa(dst_addr), difference);
	}

	fflush(stdout);
	usleep(sleep_amount);
	ctr++;

	if(use_counter && ctr >= counter){
		break;
	}
    }

    return 0;
}

void parse_argvs(int argc, char **argv, struct in_addr *src, struct in_addr *esrc, 
			struct in_addr *edst, int *both, int *counter, useconds_t *sleep_counter, int *rand_init)
{
	int c = 0;
	opterr = 0;
	int retval = 0;

	inet_aton("0.0.0.0", esrc);
	inet_aton("0.0.0.0", edst);
	inet_aton("0.0.0.0", src);

	///Use getopt to parse the four cmd-line options -s -d -S and -D.
	while((c = getopt(argc, argv, "z:c:bs:S:D:hr:")) != -1){
		switch(c){
			case 'r':
				*rand_init = atoi(optarg);
				break;
			case 'z':
				*sleep_counter = strtoul(optarg, NULL, 10);
				break;
			case 'c':
				*counter = atoi(optarg);
				break;
			case 'b':
				*both = 1;
				break;
			///get the source IP 
			case 's':
				retval = inet_aton(optarg, src);
				if(retval == 0){
					fprintf(stderr, "-s <%s> problem\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;

			//get the extended source IP
			case 'S':
				retval = inet_aton(optarg, esrc);
				if(retval == 0){
					fprintf(stderr, "-S <%s> problem\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;
			
			//get the extended destination IP
			case 'D':
				retval = inet_aton(optarg, edst);
				if(retval == 0){
					fprintf(stderr, "-D <%s> problem\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;
			case 'h':
				usage();
				break;
			default:
				printf("unknown cmd-line option '%c'\n", c); fflush(stdout);
				exit(EXIT_FAILURE);
		}
	}

	if(src->s_addr == 0){
		fprintf(stderr, "One or both of -s and -d is NULL\n");
		usage();
		exit(EXIT_FAILURE);
	}
}

void usage()
{
    fprintf(stderr, "\nUsage: pinger -d [destination] -s [source]\n");
    fprintf(stderr, "\t\t-S [extended_src_ip] -D [extended_dst_ip]\n");
}
	

/*
///this function is not safe to use since a second call to inet_ntoa overwrites the static buffer.
///still, a useful function to learn from though.
char* getip()
{
    char buffer[256];
    struct hostent* h;
    
    gethostname(buffer, 256);
    h = gethostbyname(buffer);
    
    return inet_ntoa(*(struct in_addr *)h->h_addr);
    
}
*/

