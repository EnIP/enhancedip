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


#endif
