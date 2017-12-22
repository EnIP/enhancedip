#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
//#include <unistd.h>



int main(int argc, char **argv)
{
	struct in_addr in;
	unsigned long cksum = 0x14fe9;

	printf("adding of bytes cksum=0x%x\n", cksum);
	
	//printf("0x%x\n", ~0xb015 & 0xFFFF) ;
	//printf("0x%x\n", ~0x4fea & 0xFFFF);

	cksum= (cksum>>16) + (cksum&0xffff); 
	printf("cksum fold 1=0x%x\n", cksum);

	cksum += (cksum >> 16);
	printf("cksum fold 2=0x%x\n", cksum);

	printf("cksum fold 3=0x%x\n", (unsigned short)(~cksum));

/*
	inet_aton(argv[1], &in);

	printf("htonl(%x)  ntohl(%x)\n", htonl(in.s_addr), ntohl(in.s_addr));
*/
	return 0;
}
