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
#include <sys/stat.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include "lib.h"

#if 0
#include <linux/ip.h>
#include <linux/icmp.h>
#endif

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "hexdump.h"
#include "mytypes.h"
#include "oping.h"
//#include "icmp.h"

int get_source_addr(struct in_addr *);
int64 find_mode(int64 *, int );
unsigned short in_cksum(unsigned short *, int);
void parse_argvs(int, char**, struct in_addr *, struct in_addr *, struct in_addr *, struct in_addr *, 
		int *, useconds_t *, int *);
void usage(char *);
char* getip();

char *parse_route_table(char *rt, int len)
{
	char *p = NULL;
	char *save = NULL;
	int x = 0;

	char str[] = "this string is a test\a" 
	             "of my ability to program\a";

	//hexdump(rt, len);

	p = strtok(rt, "\a");
	printf("p='%s'\n", p);
	while(1){
		p = strtok(NULL, "\a");
		printf("pp=%s\n", p);
		if(!p){ break;}
	}
	

}

int get_source_addr(struct in_addr *addr)
{
	FILE *fd = 0;
	struct stat sb;
	char *p;
	char buf[4096];
	int x = 0;
	char *interface;
	unsigned long d, g;
	int line = 0;
	struct ifaddrs *ifaddr, *ifa;
	int family, s;
	char host[NI_MAXHOST];

	fd = fopen("/proc/net/route", "r");
	if(fd < 0){ return 0; }

	while(fgets(buf, sizeof(buf), fd)) {
		if(line > 0){
		   p = buf;

		   while(*p && !isspace(*p)){
			p++;
		   }
		   *p = 0x00;
		   break;

		}

		memset(buf, 0, sizeof(buf));
		line++;
	}
	//printf("interface='%s'\n", buf);

        if (getifaddrs(&ifaddr) == -1){
	        perror("getifaddrs");
		exit(EXIT_FAILURE);
	}

	//find the IP address for the default interface
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
	                  if (ifa->ifa_addr == NULL)
			                     continue;

		family = ifa->ifa_addr->sa_family;

		if (family == AF_INET ) {
		         s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) :
				         sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (s != 0) {
				printf("getnameinfo() failed: %s\n", gai_strerror(s));
				exit(EXIT_FAILURE);
			}

			if(strcmp(ifa->ifa_name, buf) == 0){
				//printf("\tifa_name=%s address: <%s>\n",ifa->ifa_name, host);
				inet_aton(host, addr);
				goto cleanup;
			}
		}
	}
		
cleanup:
        freeifaddrs(ifaddr);
	if(fd) { fclose(fd); }
	return 0;
		
}

static int comparenums(const void *p1, const void *p2)
{
	int *a, *b;
	a = (int *)(p1);
	b = (int *)(p2);

	if(*a < *b){
		return -1;
	}
	else if(*a == *b){
		return 0;
	}
	else{
		return 1;
	}
}


/*
int reverse_lookup(struct in_addr replyip, char *hostname)
{
	char service[NI_MAXSERV] = {0};
	struct sockaddr_in ip4addr;
	memset(&ip4addr, 0, sizeof(struct sockaddr_in));
	ip4addr.sin_family = AF_INET;
	ip4addr.sin_port = htons(0);
	inet_pton(AF_INET, inet_ntoa(replyip), &ip4addr.sin_addr);

	int s = getnameinfo((struct sockaddr *) &ip4addr, sizeof(struct sockaddr_in), 
				hostname, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV);
	if(s==0){
		//printf("Host: '%s'\n", hostname);
		return 0;
	}else{
		//printf("Failed getnameinfo()\n");
		return -1;
	}
}
*/

int main(int argc, char* argv[])
{
    int x = 0;
    int retval = 0;
    unsigned int exit_ctr = 0;  
    unsigned int use_exit_counter = 0;
    int counter = 0;
    struct in_addr src_addr;
    struct in_addr dst_addr;
    struct in_addr extended_src;
    struct in_addr extended_dst;
    struct in_addr replyip;
    useconds_t sleep_amount = 100000;  ///set default to 100000  microseconds = 1/10 of 1 second
    int64 difference = 0;
    uint64 r_mean = 0;  //mean travel time for ICMP packets that are "Regular"
    uint64 r_count = 0;
    uint64 o_mean = 0;  //mean travel time for ICMP packets that contain IP "Options"
    uint64 o_count = 0;
    int64 *diffarray1 = NULL;
    int64 *diffarray2 = NULL;
    int64 r_mode = 0;
    int64 o_mode = 0;
    int with_options = 0;
    char answer[1024] = {0};
    int len = 0;
    int retval2 = 0;

    if (getuid() != 0)
    {
	fprintf(stderr, "%s: root privelidges needed\n", *(argv + 0));
	exit(EXIT_FAILURE);
    }
    
    get_source_addr(&src_addr);

    parse_argvs(argc, argv, &dst_addr, &src_addr, 
    		&extended_src, &extended_dst, &counter, &sleep_amount, &with_options);

    for(x=1;x<256;x++){
	if(with_options)
           retval = otraceroute_icmp(dst_addr, src_addr, extended_src, extended_dst, &replyip, x, &difference);	
	else
           retval = rtraceroute_icmp(dst_addr, src_addr, &replyip, x, &difference);	

	if(retval < 0){
		printf("fatal error on ttl %d\n", x);
	}
	else if(retval==100){ 
		printf(".\n");
	}
	else{
    		char hostname[NI_MAXHOST] = {0};

		retval2 = reverse_lookup(replyip, &hostname[0]);
		
		printf("reply from %s, (%s), %lld\n", inet_ntoa(replyip), 
							(retval2==0)?hostname:"", difference);
		if(retval == 0)
			break;
	}

	usleep(sleep_amount);
    }

    return 0;
}

/**
	assumes array is sorted in ascending order.
	finds the value of the array element that occurs
	most frequently.
*/
int64 find_mode(int64 *array, int counter)
{
	int repeat_ctr = 0;
	int64 current_winner_offset = 0;
	int64 current_winner_ctr = 0;
	int64 lastnumber = 0;
	int x = 0;
	
	lastnumber = array[0];
	current_winner_offset = 0;
	current_winner_ctr = 1;
	repeat_ctr = 1;

	for(x=1;x<counter;x++){
		if(array[x] == lastnumber){
			repeat_ctr++;
			if(repeat_ctr > current_winner_ctr){
				current_winner_offset = x;
				current_winner_ctr = repeat_ctr;
			}
		}
		else{
			repeat_ctr=1;
		
		}

		lastnumber = array[x];
	}

	return array[current_winner_offset];

}

void parse_argvs(int argc, char **argv, struct in_addr *dst, struct in_addr *src, struct in_addr *esrc, struct in_addr *edst, 
		int *counter, useconds_t *sleep_counter, int *with_options)
{
	int c = 0;
	opterr = 0;
	int retval = 0;

	inet_aton("0.0.0.0", dst);
	inet_aton("0.0.0.0", src);
	inet_aton("1.1.1.1", esrc);
	inet_aton("2.2.2.2", edst);

	///Use getopt to parse the four cmd-line options -s -d -S and -D.
	while((c = getopt(argc, argv, "d:ho")) != -1){
		switch(c){
			///turns on ip options
			case 'o':
				*with_options = 1;
				break;
			//get the destination IP
			case 'd':
				retval = inet_aton(optarg, dst);
				if(retval == 0){
					fprintf(stderr, "-d <%s> problem\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;
			case 'h':
				usage(argv[0]);
				break;
			default:
				printf("unknown cmd-line option '%c'\n", c); fflush(stdout);
				exit(EXIT_FAILURE);
		}
	}

	//if(dst->s_addr == 0 || src->s_addr == 0){
	if(dst->s_addr == 0){
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
}

void usage(char *prog)
{
    fprintf(stderr, "\nUsage:\n %s -d <dstip>\n", prog);
    fprintf(stderr, "\nOptional:\n");
    fprintf(stderr, "\t-o \n");
    //fprintf(stderr, "\t\t-S <extended_srcip> -D <extended_dstip>\n");
    //fprintf(stderr, "\t\t-c <count> -z <sleep counter>\n");
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

