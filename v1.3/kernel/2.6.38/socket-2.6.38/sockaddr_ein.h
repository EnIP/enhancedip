#ifndef __SOCKADDR_H
#define __SOCKADDR_H

///enhanced ip (enip)

#pragma pack(1)

struct sockaddr_ein {
	unsigned short sin_family;
	unsigned short sin_port;
	struct in_addr sin_addr1;
	struct in_addr sin_addr2;
	char __pad[14];
};

#endif

