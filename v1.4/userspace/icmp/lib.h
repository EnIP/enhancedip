#ifndef __LIB_H
#define __LIB_H 1
#include "mytypes.h" 

extern int64 compute_difference(struct timeval , struct timeval );
extern int reverse_lookup(struct in_addr replyip, char *hostname);

#endif


