#ifndef __IP_H
#define __IP_H

#pragma pack(1)

struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char ihl:4;
    unsigned char version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char version:4;
    unsigned char ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
  };

struct ipopt
{
    unsigned char optionid;
    unsigned char option_length;
    unsigned short esp:1;
    unsigned short edp:1;
    unsigned short reserved:14;
    unsigned int extended_saddr;
    unsigned int extended_daddr;
};


#endif
