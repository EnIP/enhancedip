#ifndef __CHECKSUM_H
#define __CHECKSUM_H 1

#include "tcp.h"

extern unsigned short TCP_CHECKSUM(unsigned int saddr, unsigned int daddr, unsigned short protocol,
                                struct tcphdr *tcp, unsigned short tcp_len);

extern unsigned short tcp_checksum(unsigned short *, int );
extern unsigned short in_cksum(unsigned short *, int);

#endif

