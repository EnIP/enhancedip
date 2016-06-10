/*
 *    pinger.c 
 *    This is a ping imitation program 
 *    It will send an ICMP ECHO packet to the server of 
 *    your choice and listen for an ICMP REPLY packet
 *    Have fun!
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <pthread.h>

#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"

#include "mytypes.h"
#include "hexdump.h"
#include "checksum.h"

#define OPTION_LENGTH 12

struct threaddata *td = NULL;
struct in_addr g_replyip;
struct timeval before;
struct timeval after;
int DEBUG_TCP = 0;
int retval_global = 0;
extern char *network_card;

unsigned short tcp_checksum(unsigned short *, int );
unsigned short in_cksum(unsigned short *, int);
int process_icmp_reply(char *, size_t , struct in_addr *);
void display_tcp_buffer(char *, int );
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void *pcap_loop_thread();
void *send_packet_thread();

/**
	rtraceroute_tcp - Send a TCP SYN packet in an IP packet, the packet may contain data usually the string 'EnIP'.
*/
int trace_tcp(struct in_addr dst, struct in_addr src, struct in_addr *replyip, int ttl, 
			unsigned short sport, unsigned short dport,  char *data, unsigned short data_len, int64 *difference)
{
	char *packet = NULL;
	char *reply_buffer = NULL;
	struct iphdr *ip = NULL;
	struct tcphdr *tcp = NULL;
	struct ipopt *options = NULL;
	struct timeval tv;
	int packet_size = 0;
	unsigned short ip_len = sizeof(struct iphdr);
	unsigned short tcp_len = sizeof(struct tcphdr) + data_len;  ///sending string 'EnIP', which is 4 bytes in packet as an ID
	int sockfd = 0;
	int retval = 1;
	int esp = 0;
	int edp = 0;
	size_t bytesread = 0;
	char *checksum = NULL; 
        pcap_t *ph = NULL;
    	pthread_t th1,th2;
	void *ret; 

	packet_size = ip_len + tcp_len;
	if(packet_size > 1514) return -1;

	ip = calloc(1, ip_len);
	tcp = calloc(1, tcp_len);
	packet = calloc(1, packet_size);
	reply_buffer = calloc(1, packet_size+1500);

	if(!ip || !tcp || !packet || !reply_buffer){
		return -1;
	}

	ip->version = 4;
	ip->ihl = 5; 
	ip->tos	= 0x00;
	ip->tot_len = ip_len + tcp_len;
	ip->id	= htons(0x0001);
	ip->frag_off = htons(0x0000); //was 0x4000
	ip->ttl = ttl;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = src.s_addr;
	ip->daddr = dst.s_addr;

	tcp->source = htons(sport);
	tcp->dest   = htons(dport);
	tcp->seq    = htonl(0x3039);
	tcp->ack_seq = htonl(0x00000000);                                
	tcp->doff   = 5;
	tcp->syn    = 1;	
	tcp->window = htons(0x2000);
	tcp->check = 0;
	memcpy((unsigned char *)tcp+sizeof(struct tcphdr), data, data_len);

	tcp->check=TCP_CHECKSUM(ip->saddr, ip->daddr, IPPROTO_TCP, tcp, tcp_len);

	ip->check      = in_cksum((unsigned short *)ip, ip->ihl*4);

	memcpy(packet, ip, ip_len);
	memcpy(packet+ip_len, tcp, tcp_len);

	memset(&before, 0, sizeof(struct timeval));
	memset(&after, 0, sizeof(struct timeval));
	gettimeofday(&before, NULL);

	//initialize our pcap handle 'ph'
	setup_pcap(&ph, dport);

	//thread 1 calls pcap_loop()
    	pthread_create(&th1, NULL, pcap_loop_thread, ph);

	td = calloc(1, sizeof(struct threaddata));
	if(!td){ perror("calloc"); exit(EXIT_FAILURE);}	

	//thread 2 opens a socket and calls sendto()
	td->packet      = calloc(1, ip->tot_len);
	if(!td->packet) { perror("calloc"); exit(EXIT_FAILURE); }
	memcpy(td->packet, packet, ip->tot_len);
	td->packet_size = ip->tot_len;
	memcpy(&td->dst, &dst, sizeof(dst));
    	pthread_create(&th2, NULL, send_packet_thread, NULL);

	sleep(2);

	int rett = 0;
	rett = pthread_cancel(th1);
	rett = pthread_cancel(th2);

	pthread_join(th1, &ret);
	pthread_join(th2, &ret);
	
	gettimeofday(&after, NULL);

	*difference = compute_difference(before, after)/1000;

cleanup:
	if(ph) { pcap_close(ph); }
	if(ip){ free(ip); }
	if(tcp){ free(tcp); }
	if(packet){ free(packet); }
	if(options){ free(options); }
	if(reply_buffer){ free(reply_buffer);}

    	return retval_global;
}

void *pcap_loop_thread(void *ph)
{
	int retval = 0;
	pcap_t *pcap_handle = (pcap_t *)ph;

	pcap_loop(pcap_handle, 1, got_packet, NULL);

}

void *send_packet_thread()
{
	int sockfd = 0;
	int retval = 0;
	struct sockaddr_in connection;
	struct timeval tv;
	int optval = 1;  //BUG when this is set to 0

        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(sockfd == -1){
                perror("socket");
                exit(EXIT_FAILURE);
        }

        ///set the timeout to 3 seconds
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        retval = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                            (struct timeval *)&tv, sizeof(struct timeval));
        if(retval == -1){
                perror("setsockopt timeout");
                exit(EXIT_FAILURE);
        }

        ///tell it we're specifying the IP header
        retval = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));
        if(retval == -1){
                perror("setsockopt");
                exit(EXIT_FAILURE);
        }

	memset(&connection, 0, sizeof(connection));
        connection.sin_family = AF_INET;
        connection.sin_addr.s_addr = td->dst.s_addr;

        retval = sendto(sockfd, td->packet, td->packet_size, 0, (struct sockaddr *)&connection, sizeof(struct sockaddr));
        if(retval == -1){
                perror("sendto");
                exit(EXIT_FAILURE);
        }

	close(sockfd);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	int retval = 0;
	char hostname[NI_MAXHOST] = {0}; 

	retval_global = process_tcp_reply(packet+14, header->caplen-14, &g_replyip);

	//retval = reverse_lookup(g_replyip, &hostname[0]);

        //printf("reply from %s, (%s)\n", inet_ntoa(g_replyip),
         //                                 (retval==0)?hostname:".");
}

int setup_pcap(pcap_t **ph, int dstport)
{
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        //char filter_exp[1024] = "ip host ";  	/* filter expression */
        struct bpf_program fp;                 	/* compiled filter program (expression) */
        bpf_u_int32 net;   			/* ip */
        int num_packets = 1;   			/* number of packets to capture */
        char *dev = network_card;		/* "eth0" most of the time */
        bpf_u_int32 mask;
        //char filter_exp[1024] = "ip host ";  	/* filter expression */
        char filter_exp[1024] = "icmp or tcp src port ";  /* filter expression */
	char tcpflags[512] = "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0";
	char filter_buf[2048] = {0};
	int retval = 0;

	snprintf(filter_buf, 2048, "%s%d and %s", filter_exp, dstport, tcpflags);
 
        //printf("INFO: filter_buf = '%s'\n", filter_buf);
        *ph = pcap_open_live(network_card, 1514, 0, 1000, errbuf);
        if(*ph == NULL){
                perror("pcap");
                exit(EXIT_FAILURE);
        }

        /* get network number and mask associated with capture device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
                net = 0;
                mask = 0;
        }

	/* compile the filter expression */
 	if (pcap_compile(*ph, &fp, filter_buf, 0, net) == -1) {
  		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_buf, pcap_geterr(*ph));
	  	exit(EXIT_FAILURE);
 	}

	/* apply the compiled filter */
 	if (pcap_setfilter(*ph, &fp) == -1) {
  		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_buf, pcap_geterr(*ph));
  		exit(EXIT_FAILURE);
 	}

	return 0;
}

/**
	oping - Send a TCP SYN packet in an IP packet that has 12 bytes of IP options.
		The IP options are either filled with zero or may be filled with the contents of esrc and edst.
*/
int trace_tcp_options(struct in_addr dst, struct in_addr src, struct in_addr esrc, struct in_addr edst, struct in_addr *replyip, int ttl, 
			unsigned short sport, unsigned short dport, char *data, unsigned short data_len, int64 *difference)
{
	char *packet = NULL;
	char *reply_buffer = NULL;
	struct iphdr *ip = NULL;
	struct tcphdr *tcp = NULL;
	struct ipopt *options = NULL;
	struct sockaddr_in connection;
	struct timeval tv;
	struct timeval before;
	struct timeval after;
	int optval = 1;  //BUG when this is set to 0
	int packet_size = 0;
	int ip_len = sizeof(struct iphdr) + OPTION_LENGTH;
	int tcp_len = sizeof(struct tcphdr) + data_len;  ///sending string 'EnIP', which is 4 bytes in packet as an ID
	int sockfd = 0;
	int retval = 1;
	int esp = 0;
	int edp = 0;
        pcap_t *ph = NULL;
    	pthread_t th1,th2;
	void *ret; 

	packet_size = ip_len + tcp_len;

	if(ip_len > (sizeof(struct iphdr)+12) || tcp_len > 1514){
		perror("packet length error");
		exit(EXIT_FAILURE);
	}

	ip = calloc(1, ip_len);
	options = calloc(1, sizeof(struct ipopt));
	tcp = calloc(1, tcp_len);
	packet = calloc(1, packet_size);
	reply_buffer = calloc(1, packet_size);

	if(!ip || !options || !tcp || !packet || !reply_buffer){
		return -1;
	}

	ip->ihl = 8; 
	ip->version = 4;
	ip->tos	= 0;
	ip->tot_len = sizeof(struct iphdr) + OPTION_LENGTH + sizeof(struct tcphdr) + data_len;
	ip->id	= htons(random());
	ip->ttl = ttl;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = src.s_addr;
	ip->daddr = dst.s_addr;

	///if we have an extended src or dst address, 
	///send the enhanced IP options header.
	if(esrc.s_addr > 0 || edst.s_addr > 0){
		if(esrc.s_addr > 0) esp = 1;
		if(edst.s_addr > 0) edp = 1;

		options->optionid = 128 + 16 + 8 + 2;   //1 00 11010 = 
							//128+ 16 + 8 + 2 = 
							//154 = 0x9A
		options->option_length = 12;
		options->esp = esp;
		options->edp = edp;
		options->reserved = 0;
		options->extended_saddr = esrc.s_addr;
		options->extended_daddr = edst.s_addr;
	}

	tcp->source = htons(sport);
	tcp->dest   = htons(dport);
	tcp->seq    = htonl(0x12345678);
	tcp->ack_seq = htonl(0x00000000);                                
	tcp->syn    = 1;	
	tcp->window = 0;
	tcp->check  = 0;
	tcp->urg    = 0;	
	tcp->doff   = 5;
	memcpy((unsigned char *)tcp+sizeof(struct tcphdr), data, data_len);

        tcp->check     = TCP_CHECKSUM(ip->saddr, ip->daddr, IPPROTO_TCP, tcp, tcp_len);
	ip->check      = in_cksum((unsigned short *)ip, ip->ihl*4);

	memcpy(packet, ip, ip_len);
	memcpy(packet+ip_len, tcp, tcp_len);
	memcpy(packet+ip_len-12, options, sizeof(struct ipopt));

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(sockfd == -1){
		perror("socket");
		exit(EXIT_FAILURE);
	}

	///set the timeout to 3 seconds
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	retval = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, 
			    (struct timeval *)&tv, sizeof(struct timeval));
	if(retval == -1){
		perror("setsockopt timeout");
		exit(EXIT_FAILURE);
	}
	
	///tell it we're specifying the IP header
	retval = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));
	if(retval == -1){
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	connection.sin_family = AF_INET;
	connection.sin_addr.s_addr = dst.s_addr;

	memset(&before, 0, sizeof(struct timeval));
	memset(&after, 0, sizeof(struct timeval));

        //initialize our pcap handle 'ph'
        setup_pcap(&ph, dport);

        //thread 1 calls pcap_loop()
        pthread_create(&th1, NULL, pcap_loop_thread, (void *)ph);

        td = calloc(1, sizeof(struct threaddata));
        if(!td){ perror("calloc"); exit(EXIT_FAILURE);}

        //thread 2 opens a socket and calls sendto()
        td->packet      = calloc(1, ip->tot_len);
        if(!td->packet) { perror("calloc"); exit(EXIT_FAILURE); }
        memcpy(td->packet, packet, ip->tot_len);
        td->packet_size = ip->tot_len;
        memcpy(&td->dst, &dst, sizeof(dst));
        pthread_create(&th2, NULL, send_packet_thread, NULL);

        sleep(2);

        int rett = 0;
        rett = pthread_cancel(th1);
        rett = pthread_cancel(th2);

        pthread_join(th1, &ret);
        pthread_join(th2, &ret);

        gettimeofday(&after, NULL);

        *difference = compute_difference(before, after)/1000;

cleanup:
	close(sockfd);
	if(ip){ free(ip); }
	if(tcp){ free(tcp); }
	if(packet){ free(packet); }
	if(options){ free(options); }
	if(reply_buffer){ free(reply_buffer);}
	
    	return retval;
}

int process_icmp_reply(char *buf, size_t len, struct in_addr *replyip)
{
        struct iphdr *ip = NULL;
        struct icmphdr *icmp = NULL;

        if(len <= 0 || !buf){
                return -1;
        }

        ip = (struct iphdr *)buf;
        if(ip->version != 4){
                return -2;
        }

        replyip->s_addr = ip->saddr;

        if(ip->protocol != 1){
                return -3;
        }

        icmp = (struct icmphdr *)(buf + ip->ihl*4);

	//printf("ip->saddr = %x\n", ip->saddr);
	//printf("ip->daddr = %x\n", ip->daddr);

        ///ICMP echo reply is our exit success code of 0
        if(icmp->type == 0 && icmp->code == 0){
		printf("Failure: icmp->type=0, icmp->code=0\n");
                return 0;
        }
        else if(icmp->type == 3 && icmp->code == 1){
                printf("Failure: received ICMP Host unreachable\n");
                return 1;
        }
        else if(icmp->type == 11 && icmp->code == 0){
                printf("Failure: received ICMP Time Exceeded\n");
                return 11;
        }
        else{
                printf("Failure: received icmp->type=%d icmp->code=%d", icmp->type, icmp->code);
                return 12;
        }

        return -4;
}

int process_tcp_reply(char *buf, size_t len, struct in_addr *replyip)
{
	struct iphdr *ip;
	
	if(len<=0 || !buf){
		perror("bad args");
		exit(EXIT_FAILURE);	
	}

	ip = (struct iphdr *)buf;
	replyip->s_addr = ip->saddr;

	if(ip->protocol == IPPROTO_ICMP){
		printf("Failure: got ICMP packet.\n");
		return process_icmp_reply(buf, len, replyip);
	}
	else if(ip->protocol == IPPROTO_TCP){
		if(DEBUG_TCP) display_tcp_buffer(buf, len);
		printf("Success: got syn/ack reply.\n");
		return 6;
	}
	else{
		printf("Failure: got other type of packet.\n");
		return 0;
	}

}

void display_tcp_buffer(char *buf, int len)
{
	struct iphdr *ip;
	struct tcphdr *tcp;

	ip = (struct iphdr *)buf;
	tcp = (struct tcphdr *)(buf + sizeof(struct iphdr));
	
	printf("ip->version = %d\n", ip->version);
	printf("ip->ihl     = %d\n", ip->ihl);
	printf("ip->tos     = %d\n", ip->tos);
	printf("ip->tot_len = %d\n", ntohs(ip->tot_len));
	printf("ip->protocol = %d\n", ip->protocol);
	struct in_addr in;
	in.s_addr = ip->saddr;
	printf("ip->saddr   = %s\n", inet_ntoa(in));
	in.s_addr = ip->daddr;
	printf("ip->daddr   = %s\n", inet_ntoa(in));

	printf("tcp->source = %d\n", ntohs(tcp->source));
	printf("tcp->dest   = %d\n", ntohs(tcp->dest));
	printf("tcp->syn    = %d\n", tcp->syn);
	printf("tcp->rst    = %d\n", tcp->rst);
	printf("tcp->psh    = %d\n", tcp->psh);
	printf("tcp->ack    = %d\n", tcp->ack);
	printf("tcp->urg    = %d\n", tcp->urg);

}


