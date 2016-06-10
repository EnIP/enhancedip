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
#include <sys/time.h>
#include <netdb.h>

#if 0
#include <linux/ip.h>
#include <linux/icmp.h>
#endif

#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"

#include <string.h>
#include <unistd.h>
#include "mytypes.h"
#include "hexdump.h"

#define OPTION_LENGTH 12

unsigned short TCP_CHECKSUM(unsigned int saddr, unsigned int daddr, unsigned short protocol,
                                struct tcphdr *tcp, unsigned short tcp_len);

unsigned short tcp_checksum(unsigned short *, int );
unsigned short in_cksum(unsigned short *, int);



/**
	Before using this routine generically make sure and cleanup the overflows.
*/
unsigned short TCP_CHECKSUM(unsigned int saddr, unsigned int daddr, unsigned short protocol, 
				struct tcphdr *tcp, unsigned short tcp_len)
{
	unsigned int loc_saddr = saddr;
	unsigned int loc_daddr = daddr;
	unsigned short loc_protocol = ntohs(protocol);
	unsigned short loc_tcp_len = ntohs(tcp_len);
	char *checksum = NULL;
	unsigned short check = 0;

	checksum = calloc(1, 1000);
	if(!checksum) return 0;

        // 4   +  4   +     2       +     2
        //ipsrc, ipdst, tcp protocol, tcp length, tcp header+data
        memcpy(checksum, &loc_saddr, 4);
        memcpy(checksum+4, &loc_daddr, 4);
        memcpy(checksum+8, &loc_tcp_len, 2);
        memcpy(checksum+10, &loc_protocol, 2);
        memcpy(checksum+12, (void *)tcp, tcp_len);
//	memcpy(checksum+(tcp_len+12), data, data_len);

        //printf("pseudo header\n");
        //hexdump(checksum, 12);

        //printf("tcp header\n");
        //hexdump(tcp, 20);

        check = tcp_checksum((unsigned short *)checksum, tcp_len+12);
        //printf("INFO: check = '0x%x'\n", check);
        //tcp->check  = htons(0xb015); 

	return check;
}

unsigned short tcp_checksum(unsigned short *buffer, int size)
{
    unsigned long cksum=0;
    while(size >1)
    {
        cksum+=*buffer++;
        size -=sizeof(unsigned short);
    }
    if(size){
        cksum += *(unsigned char *)buffer;
    }
//    printf("cksum=0x%x\n", cksum);

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);  //4fea = b015
}


/*
 * in_cksum --
 * Checksum routine for Internet Protocol
 * family headers (C Version)
 */
unsigned short in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
	  sum += *w++;
	  nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
	  *(u_char *) (&answer) = *(u_char *) w;
	  sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);		/* add hi 16 to low 16 */
    sum += (sum >> 16);				/* add carry */
    answer = ~sum;				/* truncate to 16 bits */
    return (answer);
}

