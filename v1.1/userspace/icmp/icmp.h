#ifndef __ICMP_H
#define __ICMP_H

struct icmphdr{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short id;	
	unsigned short sequence;
};

#define ICMP_ECHO 8



#endif

