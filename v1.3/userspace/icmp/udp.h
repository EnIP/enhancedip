#ifndef __UDP_H
#define __UDP_H

struct udphdr {
        unsigned short source;
        unsigned short dest;
        unsigned short len;
        unsigned short check;
};

#endif
