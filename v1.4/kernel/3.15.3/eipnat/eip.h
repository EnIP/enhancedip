#ifndef __IP_H
#define __IP_H

//#pragma pack(1)
//
#define ENIP_MAGIC 0x9a

struct extended_ip
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

