#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "mytypes.h"

int64 compute_difference(struct timeval , struct timeval );
int reverse_lookup(struct in_addr replyip, char *hostname);

/**
 * Computes the difference and returns a value in microseconds
 */
int64 compute_difference(struct timeval before, struct timeval after)
{

	//printf("before sec=%ld after sec=%ld\n", before.tv_sec, after.tv_sec);

        return (int64)(after.tv_sec - before.tv_sec) * 1000000 +
                        (after.tv_usec - before.tv_usec);
}


int reverse_lookup(struct in_addr replyip, char *hostname)
{
        char service[NI_MAXSERV] = {0};
        struct sockaddr_in ip4addr;
        memset(&ip4addr, 0, sizeof(struct sockaddr_in));
        ip4addr.sin_family = AF_INET;
        ip4addr.sin_port = htons(0);
        inet_pton(AF_INET, inet_ntoa(replyip), &ip4addr.sin_addr);

        int s = getnameinfo((struct sockaddr *) &ip4addr, sizeof(struct sockaddr_in),
                                hostname, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV);
        if(s==0){
                //printf("Host: '%s'\n", hostname);
                return 0;
        }else{
                //printf("Failed getnameinfo()\n");
                return -1;
        }
}

