#ifndef __GETADDRINFO_SHIM_H
#define __GETADDRINFO_SHIM_H

struct dns_request{
	char buf[2048];
	int len;
};

struct dnsquestions{
	unsigned char question_raw[1024];
	int rawlen;
	unsigned short qtype;
	unsigned short qclass;
	struct dnsquestions *next;
};

struct dnsanswers{
	unsigned char answer_raw[8192];
	int rawlen;
	unsigned short qtype;
	unsigned short qclass;
	unsigned int ttl;
	unsigned short datalen;
	unsigned char data[8192];
	struct dnsanswers *next;
};

struct dnspkt{
	unsigned short tid;
	unsigned short flags;
	unsigned short questions;
	unsigned short answerrr;
	unsigned short authorityrr;
	unsigned short additionalrr;

	//after this point don't dereference directly as we've processed
	//the packet to fill in these fields.
	
	//question section
	struct dnsquestions *q;
	
	//answer section
	struct dnsanswers *a;
};

struct dnsbabypkt{
	unsigned short tid;
	unsigned short flags;
	unsigned short questions;
	unsigned short answerrr;
	unsigned short authorityrr;
	unsigned short additionalrr;
};



#endif
