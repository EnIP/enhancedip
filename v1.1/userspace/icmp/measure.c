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

#if 0
#include <linux/ip.h>
#include <linux/icmp.h>
#endif

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <unistd.h>
#include "hexdump.h"
#include "mytypes.h"
#include "oping.h"

int64 find_mode(int64 *, int );
unsigned short in_cksum(unsigned short *, int);
void parse_argvs(int, char**, struct in_addr *, struct in_addr *, struct in_addr *, struct in_addr *, 
		int *, useconds_t *);
void usage();
char* getip();

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
    useconds_t sleep_amount = 100000;  ///set default to 100,000 microseconds = 100 millseconds = 1/10th of a second
    int64 difference = 0;
    uint64 r_mean = 0;  //mean travel time for ICMP packets that are "Regular"
    uint64 r_count = 0;
    uint64 o_mean = 0;  //mean travel time for ICMP packets that contain IP "Options"
    uint64 o_count = 0;
    int64 *diffarray1 = NULL;
    int64 *diffarray2 = NULL;
    int64 r_mode = 0;
    int64 o_mode = 0;

    if (getuid() != 0)
    {
	fprintf(stderr, "%s: root privelidges needed\n", *(argv + 0));
	exit(EXIT_FAILURE);
    }

    parse_argvs(argc, argv, &dst_addr, &src_addr, 
    		&extended_src, &extended_dst, &counter, &sleep_amount);

    if(counter > 0){
	use_exit_counter = 1;
	
	///we use this array for obtaining the median value
	diffarray1 = calloc(1, sizeof(int64)*counter);
	diffarray2 = calloc(1, sizeof(int64)*counter);
	if(!diffarray1 || !diffarray2){
		perror("calloc");
		exit(EXIT_FAILURE);
	}
    }

    while(1) {
        retval = rping(dst_addr, src_addr, &difference);	
        if(retval < 0){
	      fprintf(stderr, "oping failure\n");
	      exit(EXIT_FAILURE);
        }
	printf("Received rping %s,%lld\n", inet_ntoa(dst_addr), difference); 
	r_mean += difference; r_count++;
	if(counter > 0){
		diffarray1[exit_ctr] = difference;
	}

        retval = oping(dst_addr, src_addr, extended_src, extended_dst, &difference);	
        if(retval < 0){
	      fprintf(stderr, "oping failure\n");
	      exit(EXIT_FAILURE);
        }
	printf("Received oping %s,%lld\n", inet_ntoa(dst_addr), difference);
	o_mean += difference; o_count++;
	if(counter > 0){
		diffarray2[exit_ctr] = difference;
	}

	fflush(stdout);

	///1000 microseconds = 1 millisecond
	///1,000,000 microseconds = 1 second
	usleep(sleep_amount);

	exit_ctr++;

	if(use_exit_counter && exit_ctr >= counter){
		break;
	}
    }

    /**
	Calculate the mean round trip time. 
    */
    double result;
    if(r_count > 1){
	result = (double)r_mean / (double)r_count;
	printf("regular mean=%f milliseconds\n", result);
    }

    if(o_count > 1){
	result = (double)o_mean / (double)o_count;
	printf("option mean=%f milliseconds\n", result);
    }

    /**
	Calculate the median round trip time.
     */ 
    if(counter > 1){
    	qsort(diffarray1, counter, sizeof(int64), comparenums);
    	qsort(diffarray2, counter, sizeof(int64), comparenums);

    	printf("regular ping median RTT = %lld\n", diffarray1[counter/2]);
    	printf("option  ping median RTT = %lld\n", diffarray2[counter/2]);

	r_mode = find_mode(diffarray1, counter);
	o_mode = find_mode(diffarray2, counter);
	printf("regular ping mode RTT = %lld\n", r_mode);
	printf("option  ping mode RTT = %lld\n", o_mode);

    	if(diffarray1) free(diffarray1);
	if(diffarray2) free(diffarray2);
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
		int *counter, useconds_t *sleep_counter)
{
	int c = 0;
	opterr = 0;
	int retval = 0;

	inet_aton("0.0.0.0", dst);
	inet_aton("0.0.0.0", src);
	inet_aton("0.0.0.0", esrc);
	inet_aton("0.0.0.0", edst);

	///Use getopt to parse the four cmd-line options -s -d -S and -D.
	while((c = getopt(argc, argv, "z:c:s:d:S:D:h")) != -1){
		switch(c){
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
				usage();
				break;
			default:
				printf("unknown cmd-line option '%c'\n", c); fflush(stdout);
				exit(EXIT_FAILURE);
		}
	}

	if(dst->s_addr == 0 || src->s_addr == 0){
		fprintf(stderr, "Must specify at least -s and -d\n\n\n");
		usage();
		exit(EXIT_FAILURE);
	}
}

void usage()
{
    fprintf(stderr, "\nUsage: measure -d [destination] -s [source]\n");
    fprintf(stderr, "\t\t-S [extended_src_ip] -D [extended_dst_ip]\n");
    fprintf(stderr, "\t\t-c [count] -z [sleep counter]\n");
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

