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

#include <sys/stat.h>
#include <ifaddrs.h>


#if 0
#include <linux/ip.h>
#include <linux/icmp.h>
#endif

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "hexdump.h"
#include "mytypes.h"
#include "oping.h"

unsigned short in_cksum(unsigned short *, int);
void parse_argvs(int, char**, struct in_addr *, struct in_addr *, struct in_addr *, struct in_addr *, 
		int *, int *, useconds_t *);
void usage(char *);
void getip(struct in_addr *);
int get_source_addr(struct in_addr *addr);

int enip_inet_aton(char *arg, struct in_addr *dst_addr, struct in_addr *extended_dst)
{
	
	char *tok = NULL;
	int x = 0;
	int retval = 0;
	int counter = 0;
	int placeholder = 0;
	inet_aton("0.0.0.0", dst_addr);
	inet_aton("0.0.0.0", extended_dst);

	//count how many periods.
	for(x=0;x<strlen(arg);x++)
		if(arg[x] == '.') counter++;

	if(counter == 3){
		retval = inet_aton(arg, dst_addr);
		if(retval == 0){
			return -1;
		}
	}
	else if(counter == 7){
		counter = 0;
		placeholder = 0;
		for(x=0;x<strlen(arg);x++){
			if(arg[x] == '.'){
				counter++;
				if(counter==4){
					arg[x]='\0';
					placeholder = x+1;
					break;
				}
			}
		}

		retval = inet_aton(arg, dst_addr);
		if(retval == 0){
			return -1;
		}

		retval = inet_aton(arg+placeholder, extended_dst); 

	}
	else{
		return -2;
	}

	return 1;
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

    ///initialize the addresses
    inet_aton("255.255.255.255", &extended_src);
    inet_aton("0.0.0.0", &extended_dst);
    inet_aton("0.0.0.0", &src_addr);
    inet_aton("0.0.0.0", &dst_addr);

    if (getuid() != 0){
	fprintf(stderr, "%s: root privelidges needed\n", *(argv + 0));
	exit(EXIT_FAILURE);
    }

    if(argc != 2){
	usage(argv[0]);
	exit(EXIT_SUCCESS);
    }
   
    ///get the source ip addr of this machine
    //getip(&src_addr);
    get_source_addr(&src_addr);

    if(enip_inet_aton(argv[1], &dst_addr, &extended_dst) == 0){
		exit(EXIT_FAILURE);
    }

//    parse_argvs(argc, argv, &dst_addr, &src_addr, &extended_src, &extended_dst, &both, &counter, &sleep_amount);

    fprintf(stderr, "Source address: %s\n", inet_ntoa(src_addr));
    fprintf(stderr, "Destination address: %s.", inet_ntoa(dst_addr));
    fprintf(stderr, "%s\n", inet_ntoa(extended_dst));

    if(counter > 0){
	use_counter = 1;
    }

    while(1)
    {
	//printf("INFO: extended_src.s_addr = 0x%x\n", extended_src.s_addr);
        if(extended_src.s_addr != 0xffffffff || extended_dst.s_addr){
	   //oping = ping with IP+Options+ICMP
           retval = oping(dst_addr, src_addr, extended_src, extended_dst, &difference);	
           if(retval < 0){
	      fprintf(stderr, "oping failure\n");
	      exit(EXIT_FAILURE);
           }
	   printf("Received options ping from %s.", inet_ntoa(dst_addr)); 
	   printf("%s time=%lld ms\n", inet_ntoa(extended_dst), difference);
	}
	else{
	   //rping = regular IP+ICMP ping
           retval = rping(dst_addr, src_addr, &difference);	
           if(retval < 0){
	      fprintf(stderr, "oping failure\n");
	      exit(EXIT_FAILURE);
           }
	   printf("Received regular ping from %s, time=%lld ms\n", inet_ntoa(dst_addr), difference);
	}

	fflush(stdout);
	usleep(sleep_amount);
	ctr++;

	//if(use_counter && ctr >= counter){
	//	break;
	//}
    }

    return 0;
}

void parse_argvs(int argc, char **argv, struct in_addr *dst, struct in_addr *src, struct in_addr *esrc, 
			struct in_addr *edst, int *both, int *counter, useconds_t *sleep_counter)
{
	int c = 0;
	opterr = 0;
	int retval = 0;

	inet_aton("255.255.255.255", esrc);
	inet_aton("0.0.0.0", edst);
	inet_aton("0.0.0.0", src);
	inet_aton("0.0.0.0", dst);


	///get source ip address unless it's replaced later with -s <srcip> 
	getip(src);

	///Use getopt to parse the four cmd-line options -s -d -S and -D.
	while((c = getopt(argc, argv, "z:c:bs:d:S:D:h")) != -1){
		switch(c){
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

	if(dst->s_addr == 0 || src->s_addr == 0){
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
}

void usage(char *program_name)
{
	fprintf(stderr, "\n\n%s 2.2.2.2\n", program_name);
	fprintf(stderr, "\n\n%s 2.2.2.2.10.1.1.2\n", program_name);
	fprintf(stderr, "\n\n");
}
	


///this function is not safe to use since a second call to inet_ntoa overwrites the static buffer.
///still, a useful function to learn from though.
///http://stackoverflow.com/questions/1570511/c-code-to-get-the-ip-address
void getip(struct in_addr *src)
{
    int fd;
    struct ifreq ifr;
    char *ipaddr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    snprintf(ifr.ifr_name, IFNAMSIZ, "wlan0");

    ioctl(fd, SIOCGIFADDR, &ifr);

    /* and more importantly */
    //printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    //printf("%lx\n", ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

    close(fd);

    ipaddr = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

    inet_aton(ipaddr, src);
    //printf("ipaddr = %s\n", ipaddr);
    //printf("src=%lx\n", *src);

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

