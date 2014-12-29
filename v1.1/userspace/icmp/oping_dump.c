#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef WIN32
#include "pcap.h"
#endif

#ifndef WIN32
#include <pcap.h>
#endif

#include "hexdump.h"
#include "ip.h"
#include "icmp.h"

#if 0
#include <linux/icmp.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TRUE 1

char *srcip = NULL;


typedef struct packetinfo{
	u_char *pkt;
        int len; 
	const struct pcap_pkthdr *hdr;
}pktinfo_t;


typedef struct state_type{
	char *outfile;
	int l2len;
	void (*callback)(void *);
	u_char *curpkt;
	int curlen;
	const struct pcap_pkthdr *hdr;
}state_t;

void print_extended_ip(struct iphdr *, struct ipopt *);
char *my_inet_ntoa(struct in_addr );
void process_oping(state_t *, char *, int );
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int  for_single_packet(u_char *, int , const struct pcap_pkthdr *, state_t *);
void file_read_callback(u_char *, const struct pcap_pkthdr *, const u_char *);
void nic_read_callback(u_char *, const struct pcap_pkthdr *, const u_char *);
int  find_magic_icmp(char *interface_name, char *filename, u_char *pktbuf, int len, int l2len, void (*callback)(void *), char *);

int find_magic_icmp(char *interface_name, char *infilename, u_char *pktbuf, int len, int l2len, void (*callback)(void *), char *outfile)
{
	state_t state;

	if(!interface_name && !infilename && !pktbuf){ return -1; }
	if(interface_name && infilename){ return -2; }
	if(interface_name && pktbuf) { return -3; }
	if(infilename && pktbuf) { return -4; }
	if(pktbuf && len <= 0) { return -5; }
	if(pktbuf && l2len < 0) { return -6; }
	if(!callback){ return -7; }

	if(infilename){
		return foreach_pkt_infile(infilename, callback, outfile);
	}
	
	if(interface_name){
		return foreach_pkt_on_interface(interface_name, callback, outfile);
	}

	if(pktbuf){
		state.l2len    = l2len;
		state.callback = callback;
		state.outfile  = outfile;
		return for_single_packet(pktbuf, len, NULL, &state);
	}
}

int foreach_pkt_on_interface(char *interface_name, void (*callback)(void *), char *outfile)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *adhandle;
	state_t state;

	if ((adhandle= pcap_open_live(interface_name,
                                                 65536,
                                                 1,
                                                 1000,
                                                 errbuf
                                                 )) == NULL)
	{
        	return -1;
	}

	state.l2len = pcap_l2len(adhandle);
	state.callback = callback;
	state.outfile = outfile;

	pcap_loop(adhandle, 0, nic_read_callback, (u_char *)&state);
	pcap_close(adhandle);

}

int for_single_packet(u_char *pktbuf, int len, const struct pcap_pkthdr *hdr, state_t *state)
{
	struct iphdr *ip;
	struct icmphdr *icmp;
	unsigned int *deadbeef;
	struct in_addr src;

	state->curpkt = pktbuf;
	state->curlen = len;
	state->hdr = hdr;

	ip = (struct iphdr *)(state->curpkt + state->l2len);

	//inet_aton("65.127.220.42", &src);
	//inet_aton(srcip, &src);

	if(ip->protocol == 1){

		//hexdump(pktbuf, len);
		icmp = (struct icmphdr *)(state->curpkt + state->l2len +  (ip->ihl*4));
		if(icmp->type == ICMP_ECHO){
		
			//we expect 0xDEADBEEF to be in the ICMP echo request with IP options.
			deadbeef = (unsigned int *)(state->curpkt + state->l2len + (ip->ihl*4) + 4);
			if(ntohl(*deadbeef) == 0xDEADBEEF){
				process_oping(state, pktbuf, len);
			}
		}
	}

	return 0;
}

void process_oping(state_t *state, char *pktbuf, int len)
{
	struct iphdr *ip;
	struct in_addr saddr;
	struct in_addr daddr;
	char *src = NULL;
	char *dst = NULL;
	struct ipopt *opt = NULL;

        ip = (struct iphdr *)(state->curpkt + state->l2len);
	if(ip->ihl == 8){
		opt = (struct ipopt *)(state->curpkt + state->l2len + 20);
		if(opt->optionid == 0x9A){
			print_extended_ip(ip, opt);
		}
	}

/*
	saddr.s_addr = ip->saddr;
	daddr.s_addr = ip->daddr;
	
	dst = my_inet_ntoa(daddr);
	src = my_inet_ntoa(saddr);

	printf("oping received, %s => %s\n", src, dst);
	printf("oping sending response, %s => %s\n", dst, src); 
	oping(src, dst);
	fflush(stdout);
	free(src);
	free(dst);
*/
}

char *ip2str(unsigned int x)
{
	char *p = NULL;
	int retval = 0;
	p = (char *)calloc(1, 20);
	if(!p){ return NULL; }

	retval = snprintf(p, 20, "%d.%d.%d.%d", x & 0xFF,
				       x>>8 & 0xFF,
				       x>>16 & 0xFF,
				       x>>24 & 0xFF);
	if(retval < 0){
		free(p);
		return NULL;
	}

	return p;
}

void print_extended_ip(struct iphdr *ip, struct ipopt *opt)
{
	if(!ip || !opt){ return; }
	char *src, *esrc, *dst, *edst = NULL;

	src = ip2str(ip->saddr);
	esrc = ip2str(opt->extended_saddr);
	dst = ip2str(ip->daddr);
	edst = ip2str(opt->extended_daddr);

	printf("%s.%s => ", src, esrc);
	printf("%s.%s\n", dst, edst);
}

char *my_inet_ntoa(struct in_addr in)
{
	char *b;
	register char *p;
	
	b = (char *)calloc(1, 18);
	if(!b){
		return NULL;
	}

	p = (char *)&in;


	#define UC(b) (((int)b)&0xFF)
	//printf("%d.%d.%d.%d\n", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));
	snprintf(b, 18, "%d.%d.%d.%d", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));

	return b;	
}

void file_read_callback(u_char *s, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	state_t *state;

	state = (state_t *)s;

	for_single_packet((u_char *)pkt, hdr->caplen, hdr, state);
}

void nic_read_callback(u_char *s, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	state_t *state;

	state = (state_t *)s;

	for_single_packet((u_char *)pkt, hdr->caplen, hdr, state);
}

int pcap_l2len(pcap_t *fp)
{
	int datalink_type = 0;

	datalink_type = pcap_datalink(fp);

	switch(datalink_type){
		case DLT_EN10MB:
			return 14;
			break;
		default:
			fprintf(stderr, "data link type %d is currently not supported in this code but could be added.\n", datalink_type);
			exit(-1);
			break;
	}

	return -1;
}

int foreach_pkt_infile(char *filename, void (*callback)(void *), char *outfile)
{
	pcap_t *fp = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	state_t s;

	fp = pcap_open_offline(filename, errbuf);
	if(fp == NULL){
		return -1;
	}

	s.callback = callback;	
	s.l2len = pcap_l2len(fp);
	s.outfile = outfile;

	pcap_loop(fp, 0, file_read_callback, (u_char *)&s);

	pcap_close(fp);

	return 0;
}

void ipv6_cb(void *arg)
{
	state_t *s;

	if(!arg){ return; }

	s = (state_t *)arg;

//	hexdump(s->curpkt, s->curlen);
//	printf("\n");
}


int write_pcap_hdr(char *outfile)
{
	int fd = 0;
	unsigned int x;

	fd = open(outfile, O_RDWR|O_CREAT, S_IRWXU);
	if(fd < 0){
		perror("open");
		fflush(stderr);
		fflush(stdout);
		exit(-1);
	}

	write(fd, "\xa1\xb2\xc3\xd4", 4);  //magic
	write(fd, "\x00\x2", 2);   	   //major version
	write(fd, "\x00\x4", 2);   	   //minor version
	write(fd, "\x00\x00\x00\x00", 4);  //thiszone
	write(fd, "\x00\x00\x00\x00", 4);  //sigfigs
	x=65535;  
	write(fd, &x, sizeof(x));	   //snap length
	write(fd, "\x00\x00\x00\x01", 4);  //header type

	close(fd);
}

int main(int argc, char **argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *infile = NULL;
	char *outfile = NULL;
	char *nic = NULL;
	int args = argc;
	int x = 0;
	int list_interfaces = 0; 

	for(x=0;x<args;x++){
		if(strcmp(argv[x], "-r") == 0){
			infile = argv[x+1];	
		}

		if(strcmp(argv[x], "-i") == 0){
			nic = argv[x+1];
		}
	
		if(strcmp(argv[x], "-l") == 0){
			list_interfaces = 1;
		}

		if(strcmp(argv[x], "-s") == 0){
			srcip = argv[x+1];
		}
	}

	if(infile == NULL && nic == NULL && list_interfaces == 0){
		//fprintf(stderr, "%s -r file.pcap \n", argv[0]);
		//fprintf(stderr, "%s -l\n", argv[0]);
		
		fprintf(stderr, "On Unix:\n");
		fprintf(stderr, "%s -i eth0 -s 1.1.1.1\n", argv[0]);

		//fprintf(stderr, "On Windows:\n");
		//fprintf(stderr, "%s -i \"\\Device\\NPF_{A03F2409-C668-408A-A07F-6C5D306743DA}\"\n",argv[0]);
		
		exit(0);
	}

/*	if(srcip == NULL){
		fprintf(stderr, "Must specify -s srcip\n");
		exit(0);
	}
*/

	if(infile && nic){
		fprintf(stderr, "Cannot specify -i and -r at the same time.\n");
		exit(0);
	}

	if(list_interfaces && nic || list_interfaces && infile){
		fprintf(stderr, "Cannot specify -l with any other arguments.\n");
		exit(0);
	}

	if(list_interfaces){
  		if(pcap_findalldevs(&alldevs, errbuf) == -1)
  		{
          		exit(1);
  		}

		  /* Print the list */
		printf("devs:\n");
		for(d=alldevs; d; d=d->next)
  		{
          		printf("%d. %s", ++i, d->name);
          		if (d->description)
                  		printf(" (%s)\n", d->description);
          		else
                  		printf(" (No description available)\n");
  		}

		if(i==0)
  		{
          		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
          		return -1;
  		}
		
		exit(0);

	}

	if(nic){
		find_magic_icmp(nic, NULL, NULL, 0, 0, ipv6_cb, outfile);
	}
	else{
		find_magic_icmp(NULL, infile, NULL, 0, 0, ipv6_cb, outfile);
	}



	///find_ipv6_tunnels("\\Device\\NPF_{A03F2409-C668-408A-A07F-6C5D306743DA}", NULL, NULL, 0, 0, ipv6_cb);
	///find_ipv6_tunnels(NULL, NULL, "\xde\xad\xbe\xef", 4, , 14, ipv6_cb);
	exit(0);

}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused parameters
	 */
	(void)(param);
	(void)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	
	printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);
	
}
