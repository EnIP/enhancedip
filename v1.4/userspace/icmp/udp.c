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
#include "udp.h"
#include "lib.h"
#include "checksum.h"

#include <string.h>
#include <unistd.h>
#include "mytypes.h"
#include "hexdump.h"

#define OPTION_LENGTH 12

int process_udp_reply(char *buf, size_t len, struct in_addr *replyip);

//int otraceroute_udp(struct in_addr, struct in_addr, struct in_addr, struct in_addr, struct in_addr *, int, int64 *);


/**
	oping - Send a UDP packet in an IP packet that has 12 bytes of IP options.
		The IP options are either filled with zero or may be filled with the contents of esrc and edst.
*/
int trace_udp_options(struct in_addr dst, struct in_addr src, struct in_addr esrc, struct in_addr edst, struct in_addr *replyip, int ttl, 
			unsigned short sport, unsigned short dport, int64 *difference)
{
	#define UDP_DATA_SIZE 4
	char *packet = NULL;
	char *reply_buffer = NULL;
	struct iphdr *ip = NULL;
	struct udphdr *udp = NULL;
	struct ipopt *options = NULL;
	struct sockaddr_in connection;
	struct timeval tv;
	struct timeval before;
	struct timeval after;
	int optval = 1;  //BUG when this is set to 0
	int packet_size = 0;
	int ip_len = sizeof(struct iphdr) + OPTION_LENGTH;
	int udp_len = sizeof(struct udphdr) + UDP_DATA_SIZE;  ///sending string 'EnIP', which is 4 bytes in packet as an ID
	int sockfd = 0;
	int retval = 0;
	int esp = 0;
	int edp = 0;
	packet_size = ip_len + udp_len;

	ip = calloc(1, ip_len);
	options = calloc(1, sizeof(struct ipopt));
	udp = calloc(1, udp_len);
	packet = calloc(1, packet_size);
	reply_buffer = calloc(1, packet_size);

	if(!ip || !options || !udp || !packet || !reply_buffer){
		return -1;
	}

	ip->ihl = 8;
	ip->version = 4;
	ip->tos	= 0;
	ip->tot_len = sizeof(struct iphdr) + OPTION_LENGTH + sizeof(struct udphdr) + UDP_DATA_SIZE;
	ip->id	= htons(random());
	ip->ttl = ttl;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = src.s_addr;
	ip->daddr = dst.s_addr;

	///if we have an extended src or dst address, 
	///send the enhanced IP options header.
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

	udp->source = htons(sport);
	udp->dest   = htons(dport);
	udp->len    = htons(12);
	udp->check  = 0x0000;   //0x0000 indicates checksum is not computed.	

	ip->check      = in_cksum((unsigned short *)ip, ip->ihl*4);

	memcpy(packet, ip, ip_len);
	memcpy(packet+ip_len, udp, udp_len);
	memcpy(packet+(ip_len+udp_len-UDP_DATA_SIZE), "EnIP", 4);
	memcpy(packet+ip_len-12, options, sizeof(struct ipopt));

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
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
		retval = 100;
		goto cleanup;
	}

	gettimeofday(&after, NULL);

	retval = process_udp_reply(reply_buffer, bytesread, replyip);

	*difference = compute_difference(before, after)/1000;

cleanup:
	close(sockfd);
	if(ip){ free(ip); }
	if(udp){ free(udp); }
	if(packet){ free(packet); }
	if(options){ free(options); }
	if(reply_buffer){ free(reply_buffer);}
	
    	return retval;
}



int process_udp_reply(char *buf, size_t len, struct in_addr *replyip)
{
	struct iphdr *ip;

        if(len<=0 || !buf){
                return -1;
        }


        ip = (struct iphdr *)buf;
        replyip->s_addr = ip->saddr;

        if(ip->protocol == IPPROTO_ICMP){
                printf("icmp reply received\n");
                return 1;
        }
        else if(ip->protocol == IPPROTO_UDP){
                printf("udp received\n");
                return 0;
        }
	else{
		printf("something different\n");
        	hexdump((unsigned char *)buf, len);
	}

	return 0;
}


