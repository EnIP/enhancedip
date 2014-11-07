#ifndef __OTRACEROUTE_H
#define __OTRACEROUTE_H

extern int rtraceroute(struct in_addr, struct in_addr, struct in_addr *, int, int64 *);
extern int otraceroute(struct in_addr, struct in_addr, struct in_addr, struct in_addr, struct in_addr *, int, int64 *);


#endif

