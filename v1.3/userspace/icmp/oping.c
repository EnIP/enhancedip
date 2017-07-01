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

#if 0
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif

#include <string.h>
#include <unistd.h>
#include "mytypes.h"
#include "hexdump.h"


//char dst_addr[15];
//char src_addr[15];

#define OPTION_LENGTH 12


int oping(struct in_addr, struct in_addr, struct in_addr, struct in_addr, int64 *);
int rping(struct in_addr, struct in_addr, int64 *);
int64 compute_difference(struct timeval , struct timeval );
unsigned short in_cksum(unsigned short *, int);
int process_ping_reply(char *, size_t );

/**
 * Computes the difference and returns a value in microseconds
 */
int64 compute_difference(struct timeval before, struct timeval after)
{

	//int64 result = 0;

	return (int64)(after.tv_sec - before.tv_sec) * 1000000 +
			(after.tv_usec - before.tv_usec);
}

/**

	Send a regular ICMP echo request packet to dst from src.  
	dst - destination IP 
	src - source IP address
	edst - unused, set to zero 
	esrc - unused, set to zero
	difference - the amount of time between when the ping is sent and when the reply is received.
*/
int rping(struct in_addr dst, struct in_addr src, int64 *difference)
{
	char *packet = NULL;
	char *reply_buffer = NULL;
	struct iphdr *ip = NULL;
	struct icmphdr *icmp = NULL;
	struct sockaddr_in connection;
	struct timeval tv;
	struct timeval before;
	struct timeval after;
	int optval = 1;  //BUG when this is set to 0
	int packet_size = 0;
	int ip_len = sizeof(struct iphdr);
	int icmp_len = sizeof(struct icmphdr);
	int sockfd = 0;
	int retval = 0;
	//int esp = 0;
	//int edp = 0;
	//static int x = 0;

	packet_size = ip_len + icmp_len + 12;
	ip = calloc(1, ip_len);
	icmp = calloc(1, icmp_len);
	packet = calloc(1, packet_size);
	reply_buffer = calloc(1, packet_size);
	if(!ip || !icmp || !packet || !reply_buffer){
		exit(EXIT_FAILURE);
	}

	ip->ihl = 5;
	ip->version = 4;
	ip->tos	= 0;
	ip->tot_len = packet_size;
	ip->id	= htons(random());
	ip->ttl = 64;
	ip->protocol = IPPROTO_ICMP;
	ip->saddr = src.s_addr;
	ip->daddr = dst.s_addr;

	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->id       = htons(0xdead);
	icmp->sequence = htons(0xbeef);
	icmp->checksum = in_cksum((unsigned short *)icmp, 
				   sizeof(struct icmphdr));
	ip->check      = in_cksum((unsigned short *)ip, ip->ihl*4);

	memcpy(packet, ip, ip_len);
	memcpy(packet+ip_len, icmp, icmp_len);
	memcpy(packet+ip_len+icmp_len, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 12);

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sockfd == -1){
		perror("socket");
		exit(EXIT_FAILURE);
	}

	///set the timeout to 3 seconds
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	retval = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, 
			    (struct timeval *)&tv, sizeof(struct timeval));
	if(retval == -1){
		perror("setsockopt timeout");
		exit(EXIT_FAILURE);
	}
	
	///tell it we're specifying the IP header
	retval = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, 
				&optval, sizeof(int));
	if(retval == -1){
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	connection.sin_family = AF_INET;
	connection.sin_addr.s_addr = dst.s_addr;

	memset(&before, 0, sizeof(struct timeval));
	memset(&after, 0, sizeof(struct timeval));

	gettimeofday(&before, NULL);

	retval = sendto(sockfd, packet, ip->tot_len, 0, 
			(struct sockaddr *)&connection, 
			sizeof(struct sockaddr));
	if(retval == -1){
		perror("sendto");
		exit(EXIT_FAILURE);
	} 

	//printf("Sent %d byte packet to %s\n", retval, inet_ntoa(dst));

	size_t bytesread = 0;

	bytesread = recv(sockfd, reply_buffer, 
		packet_size, 0);
	if(bytesread == -1){
		retval = -100;
		goto cleanup;
	}

	gettimeofday(&after, NULL);

	retval = process_ping_reply(reply_buffer, bytesread);

        //seconds microseconds.  1000 microseconds=1 millisecond
	*difference = compute_difference(before, after)/1000;  /// dividing by 1000 converts to milliseconds

cleanup:
	close(sockfd);
	if(ip){ free(ip); }
	if(icmp){ free(icmp); }
	if(packet){ free(packet); }
	if(reply_buffer){ free(reply_buffer);}
	
    	return retval;
}

/**
	oping - Send an ICMP echo request packet in an IP packet that has 12 bytes of IP options.
		The IP options are either filled with zero or may be filled with the contents of esrc and edst.
*/
int oping(struct in_addr dst, struct in_addr src, struct in_addr esrc, struct in_addr edst, int64 *difference)
{
	char *packet = NULL;
	char *reply_buffer = NULL;
	struct iphdr *ip = NULL;
	struct icmphdr *icmp = NULL;
	struct ipopt *options = NULL;
	struct sockaddr_in connection;
	struct timeval tv;
	struct timeval before;
	struct timeval after;
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
	reply_buffer = calloc(1, packet_size);
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
	ip->saddr = src.s_addr;
	ip->daddr = dst.s_addr;

	///if we have an extended src or dst address, 
	///send the extended IP options header.
	if(esrc.s_addr > 0 || edst.s_addr > 0){
		if(esrc.s_addr > 0) esp = 1;
		if(edst.s_addr > 0) edp = 1;

		options->optionid = 128 + 16 + 8 + 2;   //1 00 11010 = 
							//128+ 16 + 8 + 2 = 
							//154 = 0x9A
		options->option_length = 12;
		options->esp = esp;
		options->edp = edp;
		options->reserved = 0;
		options->extended_saddr = esrc.s_addr;
		options->extended_daddr = edst.s_addr;
	}

	icmp->type = ICMP_ECHO;
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

	///set the timeout to 3 seconds
	tv.tv_sec =  3;
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
	connection.sin_addr.s_addr = dst.s_addr;

	memset(&before, 0, sizeof(struct timeval));
	memset(&after, 0, sizeof(struct timeval));

	gettimeofday(&before, NULL);

	retval = sendto(sockfd, packet, ip->tot_len, 0, (struct sockaddr *)&connection, sizeof(struct sockaddr));
	if(retval == -1){
		perror("sendto");
		exit(EXIT_FAILURE);
	} 
	//printf("Sent %d bytes to %s\n", retval, inet_ntoa(dst));

	size_t bytesread = 0;

	bytesread = recv(sockfd, reply_buffer, packet_size, 0);
	if(bytesread == -1){
		perror("recv");
		retval = -100;
		goto cleanup;
	}

	gettimeofday(&after, NULL);

	retval = process_ping_reply(reply_buffer, bytesread);

	//seconds microseconds.  1000 microseconds=1 millisecond
	*difference = compute_difference(before, after)/1000; 

cleanup:
	close(sockfd);
	if(ip){ free(ip); }
	if(icmp){ free(icmp); }
	if(packet){ free(packet); }
	if(options){ free(options); }
	if(reply_buffer){ free(reply_buffer);}
	
    	return retval;
}

int process_ping_reply(char *buf, size_t len)
{
	struct iphdr *ip = NULL;
	struct icmphdr *icmp = NULL;

	if(len <= 0 || !buf){
		return -1;
	}

	ip = (struct iphdr *)buf;
	if(ip->version != 4){
		return -2;
	}

	if(ip->protocol != 1){
		return -3;
	}	

	icmp = (struct icmphdr *)(buf + ip->ihl*4);

	if(icmp->type == 0 && icmp->code == 0){
		return 0;
	}
	else if(icmp->type == 3 && icmp->code == 1){
		printf("Received ICMP Host unreachable\n");
		return 1;
	}	
	else{
		printf("Received icmp->type=%d ", icmp->type);
		printf("icmp->code=%d\n", icmp->code);
		return 2;
	}

	return -4;
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
