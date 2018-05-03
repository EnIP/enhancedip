#ifndef __TCP_H
#define __TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>

struct tcphdr {
        unsigned short  source;
        unsigned short  dest;
        unsigned int  seq;
        unsigned int  ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u16   res1:4,
                doff:4,
                fin:1,
                syn:1,
                rst:1,
                psh:1,
                ack:1,
                urg:1,
                ece:1,
                cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u16   doff:4,
                res1:4,
                cwr:1,
                ece:1,
                urg:1,
                ack:1,
                psh:1,
                rst:1,
                syn:1,
                fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
        unsigned short  window;
        unsigned short  check;
        unsigned short  urg_ptr;
};



struct threaddata{
	char *packet;
	int packet_size;
	struct in_addr dst;
};

int trace_tcp(struct in_addr dst, struct in_addr src, struct in_addr *replyip, int ttl,
                        unsigned short sport, unsigned short dport,  char *data, unsigned short data_len, int64 *difference);

int trace_tcp_options(struct in_addr dst, struct in_addr src, struct in_addr esrc, struct in_addr edst, struct in_addr *replyip, int ttl,
                        unsigned short sport, unsigned short dport, char *data, unsigned short data_len, int64 *difference);

#endif
