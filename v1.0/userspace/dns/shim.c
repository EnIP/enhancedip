#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

//#include "sockaddr_ein.h"
#include "hexdump.h"
#include "shim.h"
#include "eip.h"

int DEBUG = 0;

#define A_LOOKUP 0x0001
#define AAAA_LOOKUP 0x0002

int dn_expand(unsigned char *, ssize_t , unsigned char *, unsigned char *, int);
int dns_decompress_names(unsigned char *, ssize_t , struct dnsanswers *);
void print_answer_sections(struct dnsanswers *);
int find_length(unsigned char *);
int dns_parse_reply(unsigned char *, ssize_t , struct dnspkt *);
int get_question_name(unsigned char *, ssize_t , unsigned char *, 
			struct dnsquestions **);
int get_answer_sections(unsigned char *, struct dnspkt *, 
			ssize_t , unsigned char *, struct dnsanswers **);

int node2sockaddr(int family, const char *node, const char *service,
		const struct addrinfo *hints,
		struct sockaddr **ai_addr, socklen_t *ai_addrlen)
{
	struct sockaddr_in *sa;
	struct sockaddr_in6 *sa6;

	int retval = 0;

	if(family == AF_INET){
	   sa = calloc(1, sizeof(struct sockaddr_in));
	   if(sa == NULL){
		return -26;
	   }

	   sa->sin_port = htons(atoi(service));
	   sa->sin_family = family;

	   retval = inet_pton(AF_INET, node, &sa->sin_addr);
	   if(retval != 1){
		goto cleanup;
	   }

	   *ai_addr = (struct sockaddr *)sa;
	   *ai_addrlen = sizeof(struct sockaddr_in);
	}
	else if(family == AF_INET6){
	   sa6 = calloc(1, sizeof(struct sockaddr_in6));
	   if(sa6 == NULL){
		return -28;
	   }

	   sa6->sin6_port   = htons(atoi(service));
	   sa6->sin6_family = AF_INET6;

	   retval = inet_pton(AF_INET6, node, &sa6->sin6_addr);
	   if(retval != 1){
		goto cleanup;
	   }

	   *ai_addr = (struct sockaddr *)sa6;
	   *ai_addrlen = sizeof(struct sockaddr_in6);
	}
	else{
	   return -27;
	}

	return 0;

	cleanup:
		if(sa){ free(sa); }
		if(sa6) { free(sa6); }
		return retval;
}

/**
 * This handles building the struct addrinfo **res in the case we are
 * dealing with node being an IPv4 or IPv6 address.
 */
int build_simple_result(int family, const char *node, const char *service,
			const struct addrinfo *hints, 
			struct addrinfo **res)
{
	struct addrinfo *ai = NULL;
	int retval = 0;

	//ai - shorthand for addrinfo struct.
	ai = calloc(1, sizeof(struct addrinfo));
	if(ai == NULL){
		return -13;
	}

	ai->ai_flags = hints->ai_flags;
	ai->ai_family = family;
	ai->ai_socktype = hints->ai_socktype;
	ai->ai_canonname = NULL;
	ai->ai_next = NULL;

	if(hints->ai_socktype == SOCK_DGRAM){ ai->ai_protocol=17; }
	else if(hints->ai_socktype == SOCK_STREAM){ ai->ai_protocol = 6;}
	else{ return -14; }

	retval = node2sockaddr(family, node, service, hints, 
					&ai->ai_addr, &ai->ai_addrlen);   
	if(retval < 0){
		goto cleanup;
	}
	
	*res = ai;

	return 0;

cleanup:
	if(ai){ free(ai); }
	return retval;
}

/**
 * If there is a '\n' at the end of a buffer
 * replace it with a '\0'
 */
void strip_newline(char *ptr)
{
	int len = 0;

	len = strlen(ptr) - 1;

	if(ptr[len] == '\n'){
		ptr[len] = '\0';
	}
}

/**
 * In the most rudimentary way, open up /etc/resolv.conf and
 * grab the first nameserver listed in it.  Make sure it's a
 * IPv4 nameserver and not an IPv6 one.
 * 
 */
int get_resolver(struct in_addr *nameserver)
{
	char line[1024] = {0};
	char *ptr = NULL;
	int retval = 0;

	FILE *file = fopen("/etc/resolv.conf", "r");
	if(file == NULL){
		perror("fopen");
		return -12;
	}

	while( fgets(line, sizeof(line), file) != NULL){

	   ptr = line;
	   while(isspace(*ptr)){ptr++;} /*skip white space*/

	   if(*ptr == '#'){  /*skip comments */
	        memset(line, 0, sizeof(line));
	    	continue;
	   }
	
	   if(strncmp(ptr, "nameserver ", 11) != 0){
	        memset(line, 0, sizeof(line));
	   	continue;
	   }

	   ptr += strlen("nameserver ");

	   while(isspace(*ptr)){ptr++;} /* skip white space */

	   strip_newline(ptr);
	
	   retval = inet_pton(AF_INET, ptr, nameserver);  
	   if(retval == 1){
	   	fclose(file);
		return 0;
	   }

	   memset(line, 0, sizeof(line));
	}

	fclose(file);
	return -11;
}

/**
 * Connect to ipaddr->s_addr on portno, return a socket file descriptor.
 */
int udp_connect(struct in_addr *ipaddr, int portno)
{
	int sfd = 0;
	struct sockaddr_in serv_addr;
	int retval = 0;
	struct timeval tv;

	sfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sfd < 0){
		return -1;
	}

	//set the timeout to 5 seconds
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	retval = setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO,
				(struct timeval *)&tv, sizeof(struct timeval));
	if(retval == -1){
		return -23;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(portno);
	serv_addr.sin_addr.s_addr = ipaddr->s_addr;

	if(connect(sfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		return -456;

	return sfd;
}

/**
 *  Convert www.google.com to \x03www\x06google\x03com
 */
int name2raw(const char *node, char **raw, int *rawlen)
{
	int len = 0;
	char *r = NULL;
	int x = -1;
	int ctr = 0;

	len = strlen(node);

	r = calloc(1, len+2);
	if(!r){
		return -515;
	}

	memcpy(r+1, node, len);
	
	for(x=len+1; x>-1; x--){
		if(r[x]=='.' || r[x]=='\0'){
			r[x] = ctr;
			ctr=0;
		}
		else{
			ctr++;
		}
	}

/*
	for(x=0;x<len+1;x++){
		printf("%.2x ", r[x]);
	}
	printf("\n");
*/

	*raw = r;
	*rawlen = len + 2;

	return 0;
}

ssize_t dns_send_request(int sfd, struct dns_request req)
{
	return write(sfd, req.buf, req.len);
}

int dns_build_request(unsigned short record_type, const char *node, 
			struct dns_request *req)
{
	struct dnsbabypkt *dns = NULL;
	char *ptr = NULL;
	unsigned short *sptr = NULL;
	char *rawname = NULL;
	int rawlen = 0;

	dns = (struct dnsbabypkt *)req->buf;

	///if the name is larger than 256 chars fail
	if(strlen(node) > 256){ 
		return -123;
	}

	memset(dns, 0, sizeof(struct dnsbabypkt));
	dns->tid = (unsigned short)random();
	dns->flags = htons(0x0100);
	dns->questions = htons(1);
	
	if(name2raw(node, &rawname, &rawlen) < 0){
		return -124;
	}

	ptr = req->buf + sizeof(struct dnsbabypkt);
	memcpy(ptr, rawname, rawlen);
	sptr = (unsigned short *)(ptr +  rawlen);
	*sptr++ = htons(record_type);	
	*sptr = htons(0x0001);

	req->len = sizeof(struct dnsbabypkt) + rawlen + 4;

	if(rawname){free(rawname);}
	return 0;
}

int dns_process_reply(int sfd, struct dns_request req, 
		 const char *node, const char *service,
		 const struct addrinfo *hints, 
		 struct addrinfo **res)
{
	struct dnspkt dnsreply;
	ssize_t cnt = 0;
	unsigned char reply_pkt[2048] = {0};

	///read the reply pkt within 5 seconds or fail
	cnt = read(sfd, reply_pkt, sizeof(reply_pkt));
	if(cnt <= 0){
		return -255;
	}

	///just parses the raw byte values, no decompression.
	if(dns_parse_reply(reply_pkt, cnt, &dnsreply) < 0){
		return -256;
	}


	if(dns_decompress_names(reply_pkt, cnt, dnsreply.a) < 0){
		return -257;
	}
	
	print_answer_sections(dnsreply.a);
	hexdump(reply_pkt, cnt);

	return 0;	
}

int dns_decompress_names(unsigned char *replypkt, ssize_t cnt, 
			struct dnsanswers *a)
{
	unsigned char exp_dn[4096] = {0};
	int elen = 4096;
	int retval = 0;
	unsigned char *comp_dn = NULL;

	while(a->next != NULL){
		
		///CNAME records
		comp_dn = a->answer_raw;
		retval = dn_expand(replypkt, cnt, comp_dn, exp_dn, elen);	
		if(retval < 0){
			return retval;
		}

		//memcpy(a->answer_raw, exp_dn, retval);

		//comp_dn = (char *)a->data;
		//dn_expand(replypkt, cnt, comp_dn, exp_dn, elen);	

		a = a->next;
	}

	return 0;
}

int dn_expand(unsigned char *replypkt, ssize_t cnt, unsigned char *comp_dn, 
		unsigned char *exp_dn, int elen)
{
	unsigned char *cn = comp_dn;
	unsigned char *en = exp_dn;
	int explen = 0;
	int clen = 0;
	unsigned short *sptr = NULL;
	unsigned short offset = 0;

	if((*cn & 0xC0) == 0xC0){
		sptr = (unsigned short *)cn;
		offset = ntohs(*sptr) & ~0xC000;
		clen = find_length(&replypkt[offset]);
		if(clen > elen){ return -1501; }

		memcpy(en, &replypkt[offset], clen); 
		//printf("clen = %d\n", clen);
	}
	else{
		clen = find_length(cn);	
		if(clen > elen){ return -1502; }
		memcpy(en, cn, clen);
	}

	printf("first pass\n");
	hexdump((unsigned char *)exp_dn, clen); 
	printf("\n");

	
	clen = find_length(en);
	if(en[clen-1] == '\0'){
		printf("null string - done\n");
		return clen;
	}
	else{
	   sptr = (unsigned short *)&en[clen-2];
	   offset = ntohs(*sptr) & ~0xC000;
	   explen = clen - 2;
	   clen = find_length(&replypkt[offset]);
	   if((explen + clen) > elen){
		return -1503;
	   }
	   memcpy(en+explen, &replypkt[offset], clen);
	}

	printf("second pass\n");
	hexdump((unsigned char *)exp_dn, explen+clen); 

	return explen+clen;
	
}



int dns_parse_reply(unsigned char *reply_pkt, ssize_t cnt, struct dnspkt *reply)
{
	struct dnspkt *t = (struct dnspkt *)reply_pkt;
	unsigned char *ptr = NULL;

	reply->tid = ntohs(t->tid);
	reply->flags = ntohs(t->flags);
	reply->questions = ntohs(t->questions);
	reply->answerrr  = ntohs(t->answerrr);
	reply->authorityrr = ntohs(t->authorityrr);
	reply->additionalrr = ntohs(t->additionalrr);

	if(reply->questions != 1){
		return -1000;
	}
	
	///pull out the question section
	ptr = (reply_pkt + sizeof(struct dnsbabypkt));
	if(get_question_name(reply_pkt, cnt, ptr, &reply->q)<0){
		return -1001;
	}
	
	//skip past the question section
	ptr = ptr + reply->q->rawlen + 4;

	if(get_answer_sections(reply_pkt, reply, cnt, ptr, &reply->a)<0){
		return -1002;
	}

	return 0;
}

void print_answer_section(struct dnsanswers *ans)
{
	hexdump((unsigned char *)ans->answer_raw, ans->rawlen);
	printf("qtype=%.4x\n", ans->qtype);
	printf("qclass=%.4x\n", ans->qclass);
	printf("ttl=%.8x\n", ans->ttl);
	hexdump((unsigned char *)ans->data, ans->datalen);
}

void print_answer_sections(struct dnsanswers *ans)
{
	int counter = 0;

	while(ans->next != NULL){
		printf("%d\n", counter+1); counter++;

		print_answer_section(ans);
		printf("\n\n");

		ans = ans->next;
	}
}

/**
 * Get the answer section and place it in a. 
 */
int get_answer_sections(unsigned char *reply_pkt, struct dnspkt *reply, 
			ssize_t cnt, unsigned char *ptr, struct dnsanswers **a)
{
	int x = 0;
	unsigned char *begin_ptr = NULL;
	unsigned short *sptr = NULL;
	unsigned int *uiptr = NULL;
	struct dnsanswers *aa = NULL;
	struct dnsanswers *first = NULL;
	struct dnsanswers *tmp = NULL;
	struct dnsanswers *prev = NULL;
	int retval = 0;
	int len = 0;
	int num_answers = 0;

	begin_ptr = ptr;

	if(reply->answerrr <= 0){
		return -1311;
	}

	num_answers = reply->answerrr;

	aa = calloc(1, sizeof(struct dnsanswers));
	if(!aa){ retval = -1312; goto cleanup; }
	first = aa;

	for(x=0;x<num_answers;x++){

		///handle the case where it's a ptr and only a ptr
		if(*ptr && 0xC0){
			///handle the ptr case
			sptr = (unsigned short *) ptr;	
			memcpy(aa->answer_raw, sptr, 2);
			aa->rawlen = 2;
			sptr++;
			aa->qtype = ntohs(*sptr); sptr++;
			aa->qclass = ntohs(*sptr); sptr++;

			uiptr = (unsigned int *)sptr;
			aa->ttl = ntohl(*uiptr); uiptr++;

			sptr = (unsigned short *)uiptr;
			aa->datalen = ntohs(*sptr); sptr++;

			ptr = (unsigned char *)sptr;

			if(aa->datalen > sizeof(aa->data)){
				retval = -1333;
				goto cleanup;
			}

			memcpy(aa->data, ptr, aa->datalen);
			//print_answer_section(aa);
			//printf("\n\n");
			ptr += aa->datalen;
		}else{
			///handle the cases where we have a
			//sequence of labels followed by a ptr
			//sequence of labels followed by a null
			printf("sequence of labels case\n");
			
			len = find_length(ptr);	
			memcpy(aa->answer_raw, ptr, len); ptr+=len;
			aa->rawlen = len;
			sptr = (unsigned short *)ptr;
			aa->qtype = ntohs(*sptr); sptr++;
			aa->qclass = ntohs(*sptr); sptr++;

			uiptr = (unsigned int *)sptr;
			
			aa->ttl = ntohl(*uiptr); uiptr++;
			
			sptr = (unsigned short *)uiptr;

			aa->datalen = ntohs(*sptr); sptr++;

			if(sizeof(aa->data) < aa->datalen){
				retval = -1353;
				goto cleanup;
			}

			ptr = (unsigned char *)sptr;

			memcpy(aa->data, ptr, aa->datalen);

			ptr = ptr + aa->datalen;
		}

		if(x<num_answers){
		   tmp = calloc(1, sizeof(struct dnsanswers));
		   if(!tmp){ retval = -1313; goto cleanup; }
		   aa->next = tmp;
		   aa = tmp;
		}
	}

	*a = first;

	return 0;

cleanup:
	///free up mem
	if(first){
		tmp = first;
		while(tmp->next != NULL){
			prev = tmp;
			tmp = tmp->next;	
			free(prev);
		}
	}

	return retval;
}

int find_length(unsigned char *ptr)
{
	unsigned char *p = ptr;
	unsigned short *sptr = NULL;
	int counter = 0;

	if(*p == 0x00){
		return 1;
	}
	else if((*p&0xC0)==0xC0){
		return 2;
	}
	else{
		while(1){
			counter++;
			if(*p == '\0'){ break;}

			sptr = (unsigned short *)p;
			if((*sptr &0xC000) == 0xC000){
				counter+=2;
				break;
			}
			p++;
		}
	}

	return counter;
}

/**
 * Find the length of a dns compressed string.
 *
 */
/*
int find_length(unsigned char *ptr)
{
	unsigned char *p = ptr;
	//unsigned short *sptr = NULL;
	int counter = 0;

	//root domain
	if(*p == 0x00){
		return 1;
	}
	//ptr to somewhere else in the packet
	else if((*p & 0xC0) == 0xC0){
		return 2;
	}

	///sequence of bytes followed by ptr or '\0' 
	while(1){
		counter = *p; 
		while(counter-- > 0){ p++; }

		if(*p == '\0'){
			if(DEBUG) printf("sob null\n");
			break;	
		}

		if((*p & 0xC0) == 0xC0){
			p+=2;
			break;
		}
	}
	
	return (int)(p - ptr);
}
*/


/**
 * Get the question name from the dns packet and store it in q.
 */
int get_question_name(unsigned char *reply_pkt, ssize_t cnt, 
			unsigned char *ptr, struct dnsquestions **q)
{
	struct dnsquestions *qq = NULL;
	int x = 0;
	int offset = 0;
	int numbytes = 0;
	unsigned short *sptr = NULL;

	qq=calloc(1, sizeof(struct dnsquestions));
	if(!qq){
		return -1003;
	}

	offset = (ptr - reply_pkt);

	//search for the null entry to find end of string
	for(x=0;x<(cnt-offset);x++){
		//printf("%.2x ", ptr[x]); fflush(stdout);
		if(ptr[x] == '\0'){
			numbytes=x+1;  //we add 1 to copy the null byte
			break;
		}
	}
		
	if(numbytes == 0){
		return -1002;
	}
	
	///copy the question name and length into our struct
	memcpy(&qq->question_raw, ptr, numbytes);
	qq->rawlen = numbytes;

	sptr = (unsigned short *)(ptr + numbytes);
	qq->qtype  = ntohs(*sptr); sptr++;
	qq->qclass = ntohs(*sptr);

	*q = qq;

	return 0;
}

int dnslookup(int type, struct in_addr *nameserver, const char *node,
		const char *service, const struct addrinfo *hints,
		struct addrinfo **res)
{
	int sfd = 0;
	struct dns_request req;
	int retval = 0;

	sfd = udp_connect(nameserver, 53);
	if(sfd < 0){
		retval = -235;
		goto cleanup;
	}

		//type = A_LOOKUP or AAAA_LOOKUP
	if(dns_build_request(type, node, &req) < 0){
		retval = -236;
		goto cleanup;
	}

	if(dns_send_request(sfd, req) < 0){
		retval = -237;
		goto cleanup;
	}

	if(dns_process_reply(sfd, req, node, service, hints, res) < 0){
		retval = -238;
		goto cleanup;
	}

	retval = 0;

cleanup:
	close(sfd);
	
	return retval;
}


/**
 * This handles building the struct addrinfo **res in the case we are
 * dealing with node being a dns name.  In other words, we have to 
 * perform the dns lookup, process the results and potentially hand back
 * a res that contains a list of results.
 */
int build_complex_result(const char *node, const char *service,
			const struct addrinfo *hints, 
			struct addrinfo **res)
{
	struct in_addr nameserver;
	int result = 0;

	srandom(time(NULL));

	///lookup the dns cache to use in /etc/resolv.conf
	if(get_resolver(&nameserver) < 0){
		return -1;
	}

	result = dnslookup(A_LOOKUP, &nameserver, node, service, hints, res);
	if(result < 0){
	   result = dnslookup(AAAA_LOOKUP, &nameserver, node, service, 
	   			hints, res);
	}
	result = -1;
	
	/*
	struct addrinfo *ai = calloc(1, sizeof(struct addrinfo));
	struct sockaddr_ein *ai_addr;
	if(ai== NULL){ return -120;}

	ai->ai_flags = hints->ai_flags;
	ai->ai_family = AF_INET;
	ai->ai_socktype = hints->ai_socktype;

	if(ai->ai_socktype == SOCK_STREAM){
		ai->ai_protocol = 6;
	}else if(ai->ai_socktype == SOCK_DGRAM){
		ai->ai_protocol = 17;
	}else{
		return -1;
	}
	ai->ai_addrlen = sizeof(struct sockaddr_ein);
	ai_addr = calloc(1, sizeof(struct sockaddr_ein));
	if(ai_addr == NULL){
		return -13;
	}

	ai_addr->sin_family = AF_INET;
	ai_addr->sin_port = htons(atoi(service));
	ai_addr->sin_addr1 = inet_addr("65.127.220.135");
	ai_addr->sin_addr2 = inet_addr("10.1.1.2");

	ai->ai_addr = (struct sockaddr *)ai_addr;

	*res = ai;
	*/

	if(result < 0){
		*res = NULL;
	}

	return 0;
}

		//hostname/ip, portnum, hints, results
int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints, 
		struct addrinfo **res)
{
	struct sockaddr_ein *eip;
	struct sockaddr_in6 copy;
	struct addrinfo *rp = NULL;
	struct stat sb;
	int retval = 0;
	void *handle = NULL;
	char *error = NULL;
	int (*getaddrinfo_ptr)(const char *node, const char *service,
				const struct addrinfo *hints, 
				struct addrinfo **res) = NULL;
	
	char *libc_location = "/lib64/libc.so.6";

	///call original getaddrinfo via dlopen/dlsym
	///the location of the libc library is machine 
	///dependant so may need changed!
	if(stat(libc_location, &sb) == -1){
		fprintf(stderr, "Error - libc is not located at %s on this"
			"system.  Time to edit some code in the getaddrinfo"
			"shim library to update the location of the C"
			"library.\n", libc_location);
		return -1;
	}

	handle = dlopen(libc_location, RTLD_LAZY);
	if(!handle){
	    	errno = EACCES;	
		return -1;
	}

	getaddrinfo_ptr = dlsym(handle, "getaddrinfo");
	if( (error = dlerror()) != NULL){
	    	fprintf(stderr, "%s\n", error);
		exit(1);
	}

	//call the original getaddrinfo in libc.
	struct sockaddr_in6 *in6 = NULL;
	retval = getaddrinfo_ptr(node, service, hints, res);
	if(retval == 0){

		/* if successful, look for our special IPv6 address*/
		for(rp = *res; rp!=NULL; rp=rp->ai_next){
			if(rp->ai_family == AF_INET6){
			   in6 = (struct sockaddr_in6 *)rp->ai_addr;
			   if(memcmp(&in6->sin6_addr.s6_addr[0], 
			   	     "\x20\x01\x01\x01", 4) == 0){
				//printf("dns shim engaged\n");
				memcpy(&copy, in6, rp->ai_addrlen);
				memset(rp->ai_addr, 0, rp->ai_addrlen);
				
				rp->ai_family = AF_INET;
				eip = (struct sockaddr_ein *)rp->ai_addr;
				eip->sin_family = AF_INET;
				eip->sin_port   = copy.sin6_port;
				memcpy(&eip->sin_addr1, 
					&copy.sin6_addr.s6_addr[4], 8);
				rp->ai_addrlen = sizeof(struct sockaddr_ein);

				//hexdump((unsigned char *)eip, 
				//	 sizeof(struct sockaddr_ein));
			   
			   }
			
			}

		}
	}
	

	return retval;
}
