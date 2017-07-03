#ifndef __ICMP_H
#define __ICMP_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "mytypes.h" 

struct icmphdr{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short id;	
	unsigned short sequence;
};

#define ICMP_ECHO 8

extern int rtraceroute_icmp(struct in_addr dst, struct in_addr src, struct in_addr *replyip, int ttl, int64 *difference);
extern int otraceroute_icmp(struct in_addr dst, struct in_addr src, struct in_addr esrc, struct in_addr edst, struct in_addr *replyip, int ttl, int64 *difference);
#endif

