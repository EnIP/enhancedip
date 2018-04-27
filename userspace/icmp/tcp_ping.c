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
#include <ctype.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
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
#include "tcp.h"


char *network_card = "eth0";

int get_source_addr(struct in_addr *);
int64 find_mode(int64 *, int );
unsigned short in_cksum(unsigned short *, int);
void parse_argvs(int, char**, struct in_addr *, struct in_addr *, struct in_addr *, struct in_addr *, 
		int *, int *, useconds_t *, int *);
void usage(char *);
char* getip();

char *parse_route_table(char *rt, int len)
{
	char *p = NULL;

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
	char *p;
	char buf[4096];
	//int x = 0;
	char *interface;
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
    char hostname[NI_MAXHOST] = {0};
    int tcpport = 80;

    if (getuid() != 0)
    {
	fprintf(stderr, "%s: root privelidges needed\n", *(argv + 0));
	exit(EXIT_FAILURE);
    }

    parse_argvs(argc, argv, &dst_addr, &src_addr, 
    		&extended_src, &extended_dst, &tcpport, &counter, &sleep_amount, &with_options);

       //retval = trace_udp_options(dst_addr, src_addr, extended_src, extended_dst, &replyip, x, 1024, 54, &difference);

    if(with_options)
        retval = trace_tcp_options(dst_addr, src_addr, extended_src, extended_dst, &replyip, 255, 40508, tcpport, "EnIP", 4, &difference);
    else
        retval = trace_tcp(dst_addr, src_addr, &replyip, 255, 40508, tcpport, "EnIP", 4, &difference);

    if(retval < 0){
        fprintf(stderr, "fatal error on ttl %d, error=%d\n", x, retval);
	exit(EXIT_FAILURE);
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
		int *tcpport, int *counter, useconds_t *sleep_counter, int *with_options)
{
	int c = 0;
	opterr = 0;
	int retval = 0;

	inet_aton("0.0.0.0", dst);
	inet_aton("0.0.0.0", src);
	inet_aton("0.0.0.0", esrc);
	inet_aton("0.0.0.0", edst);

	get_source_addr(src);

	///Use getopt to parse the four cmd-line options -s -d -S and -D.
	while((c = getopt(argc, argv, "i:z:c:s:d:S:D:hop:")) != -1){
		switch(c){
			case 'i':
				network_card = optarg;
				break;
			case 'p':
				*tcpport = atoi(optarg);
				break;
			///turns on ip options
			case 'o':
				*with_options = 1;
				break;
			case 'z':
				*sleep_counter = strtoul(optarg, NULL, 10);
				break;
			case 'c':
				*counter = atoi(optarg);
				break;
			///get the source IP 
			case 's':
				//snprintf(src, 15, "%s", optarg);
				retval = inet_aton(optarg, src);
				if(retval == 0){
					fprintf(stderr, "-s <%s> problem\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;

			//get the destination IP
			case 'd':
				retval = inet_aton(optarg, dst);
				if(retval == 0){
					fprintf(stderr, "-d <%s> problem\n", optarg);
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
				usage(argv[0]);
				break;
			default:
				printf("unknown cmd-line option '%c'\n", c); fflush(stdout);
				exit(EXIT_FAILURE);
		}
	}

	if(dst->s_addr == 0){
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
}

void usage(char *prog)
{
    fprintf(stderr, "\nUsage:\n %s -d <dstip>\n", prog);
    fprintf(stderr, "\nOptional:\n");
    fprintf(stderr, "\t\t-o \n");
    fprintf(stderr, "\t\t-i <networkcard>\n");
    fprintf(stderr, "\t\t-S <extended_srcip> -D <extended_dstip>\n");
    fprintf(stderr, "\t\t-c <count> -z <sleep counter>\n");
}
	

