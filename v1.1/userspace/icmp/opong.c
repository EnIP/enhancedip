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

#include "ip.h"
#include "icmp.h"

#if 0
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif

#include <string.h>
#include <unistd.h>
#include "hexdump.h"


char dst_addr[15];
char src_addr[15];

#define OPTION_LENGTH 12

unsigned short in_cksum(unsigned short *, int);
int opong(char *, char *, char *, char *);

int opong(char *src, char *esrc, char *dst, char *edst)
{
	char *packet = NULL;
	char *reply_buffer = NULL;
	struct iphdr *ip = NULL;
	struct icmphdr *icmp = NULL;
	struct ipopt *options = NULL;
	struct sockaddr_in connection;
	struct timeval tv;
	int optval = 1;  //BUG when this is set to 0
	int packet_size = 0;
	int ip_len = sizeof(struct iphdr) + OPTION_LENGTH;
	int icmp_len = sizeof(struct icmphdr);
	int sockfd = 0;
	int retval = 0;
	int esp = 0;
	int edp = 0;

	packet_size = ip_len + icmp_len;
	ip = calloc(1, ip_len);
	options = calloc(1, sizeof(struct ipopt));
	icmp = calloc(1, icmp_len);
	packet = calloc(1, packet_size);
	reply_buffer = calloc(1, sizeof(struct iphdr) + sizeof(struct icmphdr));
	if(!ip || !options || !icmp || !packet || !reply_buffer){
		return -1;
	}

	ip->ihl = 8;
	ip->version = 4;
	ip->tos	= 0;
	ip->tot_len = sizeof(struct iphdr) + OPTION_LENGTH + sizeof(struct icmphdr);
	ip->id	= htons(random());
	ip->ttl = 64;
	ip->protocol = IPPROTO_ICMP;
	ip->saddr = inet_addr(dst);
	ip->daddr = inet_addr(src);

	///if we have an extended src or dst address, 
	///send the extended IP options header.
	if(esrc > 0 || edst > 0){
		if(esrc > 0) esp = 1;
		if(edst > 0) edp = 1;

		options->optionid = 128 + 16 + 8 + 2;   //1 00 11010 = 
							//128+ 16 + 8 + 2 = 
							//154 = 0x9A
		options->option_length = 12;
		options->esp = esp;
		options->edp = edp;
		options->reserved = 0;
		options->extended_saddr = inet_addr(edst);
		options->extended_daddr = inet_addr(esrc);
	}

	icmp->type = 0;	///this is an ICMP_ECHOREPLY
	icmp->code = 0;
	icmp->id       = htons(0xdead);
	icmp->sequence = htons(0xbeef);
	icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr));
	ip->check      = in_cksum((unsigned short *)ip, ip->ihl*4);

	memcpy(packet, ip, ip_len);
	memcpy(packet+ip_len, icmp, icmp_len);
	//memset(packet+ip_len-12, 'B', 12);
	memcpy(packet+ip_len-12, options, sizeof(struct ipopt));

	//ip->check      = in_cksum((unsigned short *)ip, ip->ihl*4);

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sockfd == -1){
		perror("socket");
		exit(EXIT_FAILURE);
	}

	///set the timeout to 5 seconds
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	retval = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, 
			    (struct timeval *)&tv, sizeof(struct timeval));
	if(retval == -1){
		perror("setsockopt timeout");
		exit(EXIT_FAILURE);
	}
	
	///tell it we're specifying the IP header
	retval = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));
	if(retval == -1){
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	connection.sin_family = AF_INET;
	connection.sin_addr.s_addr = inet_addr(src);
	retval = sendto(sockfd, packet, ip->tot_len, 0, (struct sockaddr *)&connection, sizeof(struct sockaddr));
	if(retval == -1){
		perror("sendto");
		exit(EXIT_FAILURE);
	} 
	printf("Sending %d byte echo reply to %s.%s\n", retval, src, esrc);
	return retval;

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
