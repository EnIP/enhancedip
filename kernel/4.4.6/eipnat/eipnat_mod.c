#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/stat.h>

#include <linux/types.h>
#include <linux/icmp.h>
#include <linux/gfp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <linux/spinlock.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_nat.h>

#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_helper.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <linux/moduleparam.h>  ///to accept cmdline params from insmod
#include <linux/inet.h>        ///for in_aton function to convert IP to number

#include "eip.h"

MODULE_LICENSE("GPL");


static char *masq_ip = "0.0.0.0";
static char *nic_name = "eth0";
unsigned int outside_ip;

module_param(masq_ip, charp, 0000);
MODULE_PARM_DESC(masq_ip, "A character string");
module_param(nic_name, charp, 0000);
MODULE_PARM_DESC(nic_name, "A character string");

unsigned int apply_eip_dnat(const struct net_device *, struct sk_buff *);
unsigned int apply_eip_snat(const struct net_device *, struct sk_buff *);
void calc_checksum_unfragmented(struct sk_buff *);
void calc_checksum(struct sk_buff *);
__wsum checksum_addH(void *, int );
__wsum checksum_addN(void *, int );
uint16_t checksum_final(__wsum );

static unsigned int
nf_nat_fn(char *instring,
	  unsigned int hooknum,
	  struct sk_buff *skb,
	  const struct net_device *in,
	  const struct net_device *out,
	  int (*okfn)(struct sk_buff *))
{
	unsigned int retval = 0;

	/* maniptype == SRC for postrouting. */
	enum nf_nat_manip_type maniptype = HOOK2MANIP(hooknum);
	//printk("maniptype = %d\n", maniptype);

	/* We never see fragments: conntrack defrags on pre-routing
	   and local-out, and nf_nat_out protects post-routing. */
	NF_CT_ASSERT(!(ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET)));

	//printskb(instring, skb, in, out);
	if(maniptype == NF_NAT_MANIP_DST){
		retval = apply_eip_dnat(in, skb);
	}
	else{
		retval = apply_eip_snat(out, skb);
	}

	return retval;
}

/**
 *  Packets headed towards destination on a locally connected LAN.
 */
unsigned int apply_eip_dnat(const struct net_device *in, struct sk_buff *skb)
{
	struct iphdr *iph = NULL;
	struct extended_ip *ipopt = NULL;
	__u32 newip;

	if(!in){
		return NF_ACCEPT;	
	}
	
	//printk("nic: '%s' '%s'\n", &in->name[0], nic_name);

	if(strcmp(in->name, nic_name) != 0){
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);
	if(iph->ihl != 8){
		return NF_ACCEPT;
	}

	ipopt = (void *)skb->data + sizeof(struct iphdr); 
	if(!iph || !ipopt){ return NF_ACCEPT; }

	if(ipopt->optionid == EXTENDED_IP){
		newip      = ipopt->extended_daddr;

		iph->daddr = newip;   
		ipopt->extended_daddr = 0;
		ipopt->edp = 0;
	
		///if the packet was udp or tcp we 
		///have just messed up the checksum and need to
		///recompute it.  it is also necessary to update
		///the ip header checksum.
		calc_checksum(skb);
	}

	return NF_ACCEPT;
}

/**
 * Netfilter is nice enough to defragment the packet for us and store
 * details about the fragments in skb->data_len and skb_shinfo(skb)->frag_list
 * All the fragments are there, we just have to add them all up by 
 * traversing the frag_list linked list.
 *
 **/ 
void calc_checksum(struct sk_buff *skb)
{
	struct iphdr *iph = NULL;
	struct tcphdr *th = NULL;
	struct udphdr *uh = NULL;
	uint16_t l4len = 0;
	uint16_t iph_len = 0;
	uint16_t tcpdata_len = 0;
	uint16_t tcph_len = 0;
	uint16_t tcp_len = 0;
	uint16_t l3len = 0;
	void *l4ptr = NULL;

	iph = ip_hdr(skb);
	if(!iph){ return; }

	l3len = iph->ihl << 2;

	if(iph->protocol == IPPROTO_UDP){
	   uh = (struct udphdr *)((unsigned char *)iph + (iph->ihl<<2));
	   iph_len = l3len;
	   l4ptr = uh;
	   l4len = ntohs(uh->len);

	   uh->check = 0x0000;
	}

	if(iph->protocol == IPPROTO_TCP){
	   th = (struct tcphdr *)((unsigned char *)iph + (iph->ihl<<2));
	   tcph_len    = th->doff << 2;
	   iph_len     = l3len;
	   tcpdata_len = ntohs(iph->tot_len) - iph_len - tcph_len; 
	   tcp_len     = tcph_len + tcpdata_len;
	   l4ptr       = th;
	   l4len       = tcp_len;

	   th->check = 0x0000;
	}

	if(th){
	   th->check = csum_tcpudp_magic(iph->saddr, iph->daddr, l4len, 
	   		IPPROTO_TCP,
	   		skb_checksum(skb, iph_len, l4len, 0));
	}
	
	if(uh){
	   uh->check = csum_tcpudp_magic(iph->saddr, iph->daddr, l4len, 
	   		IPPROTO_UDP,
	   		skb_checksum(skb, iph_len, l4len, 0));
	}

	iph->check = 0;
	iph->check = ip_fast_csum((void *)iph, iph->ihl);

}

uint16_t checksum_final(__wsum sum)
{
	// Add the carries						//
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum				//
	return ( (uint16_t)htons((~sum))  );

}

/**
 * Add data that is in network byte order, converting it to host byte
 * order using ntohs() before doing the addition.
 **/
__wsum checksum_addN(void *data, int len)
{
	uint16_t *ptr = data;
	__wsum retval = 0;

	while(len > 1){
		retval += ntohs(*ptr++); 
		len-=2;
	}

	if(len & 1){
		retval += ntohs(*((uint8_t *)ptr));
	}

	return retval;
}

/**
 * Add data that is in HOST byte order
 */
__wsum checksum_addH(void *data, int len)
{
	uint16_t *ptr = data;
	__wsum retval = 0;

	while(len > 1){
		retval += *ptr++; 
		len-=2;
	}

	if(len & 1){
		retval += *((uint8_t *)ptr);
	}

	return retval;
}

/*
 * Packets headed towards the Internet, outside interface address placed
 * as source of packet.
 */
unsigned int apply_eip_snat(const struct net_device *out, struct sk_buff *skb)
{
	struct iphdr *iph = NULL;
	struct extended_ip *ipopt = NULL;

	//printk("snat out->name='%s'\n", out->name);
	if(!out || strcmp(out->name, nic_name) != 0){
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);
	if(!iph)
		return NF_ACCEPT;

	if(iph->ihl == 8){
	   ipopt = (void *)skb->data + sizeof(struct iphdr);
	   if(ipopt->optionid == EXTENDED_IP){
		ipopt->extended_saddr = iph->saddr;
		iph->saddr = outside_ip;
		ipopt->esp = 1;
		iph->check = 0;
		calc_checksum(skb);
	   }
	}

	return NF_ACCEPT;
}


static unsigned int
nf_eipnat_in(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//printk("nf_eipnat_in\n");
	return nf_nat_fn("dnat in prerouting", state->hook, skb, state->in, state->out, NULL);
}


static unsigned int
nf_eipnat_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	//printk("nf_eipnat_out\n");
	return nf_nat_fn("snat out postrouting", state->hook, skb, state->in, state->out, NULL);
}

static struct nf_hook_ops nf_nat_ops[] __read_mostly = {
	// Before packet filtering, change destination 
	{
		.hook		= nf_eipnat_in,
		//.owner		= THIS_MODULE,
		.pf		= PF_INET,		//NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_NAT_DST,
	},
	// After packet filtering, change source 
	{
		.hook		= nf_eipnat_out,
		//.owner		= THIS_MODULE,
		.pf		= PF_INET, 		//NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_NAT_SRC,
	},
};


static int __init nf_extendedip_init(void)
{
	int ret = 0;

	write_lock_bh(&dev_base_lock);

	write_unlock_bh(&dev_base_lock);


	//outside_ip = ntohl(in_aton(masq_ip));
	outside_ip = in_aton(masq_ip);

	if(outside_ip == 0){
		printk("Error: try 'insmod eipnat.ko masq_ip=\"1.1.1.1\"'\n");
		return -1;
	}

	printk("masq_ip = %s/%x\n", masq_ip, ntohl(outside_ip));
	printk("nic_name= %s\n", nic_name);

	ret = nf_register_hooks(nf_nat_ops, ARRAY_SIZE(nf_nat_ops));
	if (ret < 0) {
		printk("couldn't register nf_nat_ops\n");
		return -1;
	}
	printk("registered nf_nat_ops\n");

	return 0;
}
module_init(nf_extendedip_init);

static void __exit nf_extendedip_exit(void)
{
	nf_unregister_hooks(nf_nat_ops, ARRAY_SIZE(nf_nat_ops));
	printk("unregistered nf_nat_ops\n");
	return;
}
module_exit(nf_extendedip_exit);

