#ifndef __EIP_H
#define __EIP_H

#pragma pack(1)

struct sockaddr_ein{
	unsigned short sin_family;
	unsigned short sin_port;
	in_addr_t sin_addr1;
	in_addr_t sin_addr2;
	char __pad[14];
};

#endif
