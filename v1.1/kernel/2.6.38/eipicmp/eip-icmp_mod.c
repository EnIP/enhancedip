/*
	Very alpha prototype of ICMP Ping Daemon for Enhanced IP

*/
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
#include <net/sock.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_rule.h>
#include <net/netfilter/nf_nat_protocol.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_helper.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <linux/moduleparam.h>  ///to accept cmdline params from insmod
#include <linux/inet.h>        ///for in_aton function to convert IP to number

#include "../eip.h"

static char *eth = "eth0";
static u_char *smac = "\x08\x00\x27\x43\x97\xa2";
static u_char *dmac = "\x08\x00\x27\x76\x1d\xa2";

module_param(eth, charp, 0000);
MODULE_PARM_DESC(eth, "A character string");

//module_param(dmac, charp, 0000);
//MODULE_PARM_DESC(dmac, "A character string");

//module_param(smac, charp, 0000);
//MODULE_PARM_DESC(smac, "A character string");

unsigned int apply_eip_dnat(const struct net_device *, struct sk_buff *);
unsigned int apply_eip_snat(const struct net_device *, struct sk_buff *);

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

	/* We never see fragments: conntrack defrags on pre-routing
	   and local-out, and nf_nat_out protects post-routing. */
	NF_CT_ASSERT(!(ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET)));

	//printskb(instring, skb, in, out);
	if(maniptype == IP_NAT_MANIP_DST){
		retval = apply_eip_dnat(in, skb);
	}

	return retval;
}

/**
 icmphead->icmp_cksum = checksum(42, (unsigned short *)icmphead);
*/
static unsigned short icmp_checksum(int numwords, unsigned short *buff)
{
   unsigned long sum;
   
   for(sum = 0;numwords > 0;numwords--)
     sum += *buff++;   /* add next word, then increment pointer */
   
   sum = (sum >> 16) + (sum & 0xFFFF);
   sum += (sum >> 16);
   
   return ~sum;
}


/*
 *      The ICMP socket(s). This is the most convenient way to flow control
 *      our ICMP output as well as maintain a clean interface throughout
 *      all layers. All Socketless IP sends will soon be gone.
 *
 *      On SMP we have one ICMP socket per-cpu.
 */
/*static struct sock *icmp_sk(struct net *net)
{
        return net->ipv4.icmp_sk[smp_processor_id()];
}
*/



int sendpacket(unsigned int saddr, unsigned int daddr, unsigned int esaddr, unsigned int edaddr, char *pktdata, int pkt_len)
{

	struct sk_buff *skb = NULL;
	struct net_device *dev = NULL; 
	struct ethhdr *ethdr = NULL; 
	struct iphdr *iph = NULL; 
	u_char *pdata = NULL;
	struct icmphdr *icmph = NULL;
	int len = 0; 
	struct extended_ip *eiph = NULL;
	unsigned int sip = daddr; //__constant_htonl(0x0a030302);
	unsigned int dip = saddr; //__constant_htonl(0x02020201);
        //struct sock *sk;
        //struct rtable *rt = NULL;
	//int retval = 0;

	if(smac == NULL || dmac == NULL){
		goto out;
	}


	dev = dev_get_by_name(&init_net, eth);
	if(!dev){
		goto out;
	}

	len = (pkt_len + sizeof(struct iphdr) + sizeof(struct extended_ip) + sizeof(struct icmphdr))+LL_RESERVED_SPACE(dev);
	//len = pkt_len + sizeof(struct iphdr) + sizeof(struct extended_ip) + sizeof(struct icmphdr);

	skb = alloc_skb(len, GFP_ATOMIC);
	if (!skb)
        	return -ENOMEM;

	skb_reserve(skb, LL_RESERVED_SPACE(dev));

	skb->dev = dev; 
	skb->pkt_type = PACKET_OTHERHOST; 
	skb->protocol = __constant_htons(ETH_P_IP); 
	skb->ip_summed = CHECKSUM_NONE; 
	//skb->destructor = cup_destroy; 
	skb->priority = 0; 

	skb->network_header = skb_put(skb, sizeof(struct iphdr)+sizeof(struct extended_ip)); 
	skb->transport_header = skb_put(skb, sizeof(struct icmphdr)); 
	pdata = skb_put(skb, pkt_len); 

	memcpy(pdata, pktdata, pkt_len);

	icmph = (struct icmphdr *)skb->transport_header;
	memset(icmph, 0, sizeof(struct icmphdr));
	icmph->type = 0;
	icmph->code = 0;
	icmph->checksum = icmp_checksum(6, (unsigned short *)icmph);

	iph = (struct iphdr *) skb->network_header; 
	iph->version = 4; 
	iph->ihl = (sizeof(struct iphdr)+sizeof(struct extended_ip)) >> 2; 
	iph->frag_off = 0; 
	iph->protocol = IPPROTO_ICMP; 
	iph->tos = 0; 
	iph->ttl = 0x40; 
	iph->daddr = dip;  
	iph->saddr = sip;
	iph->tot_len = __constant_htons(skb->len); 
	iph->check = 0; 

	eiph = (struct extended_ip *)(skb->network_header + sizeof(struct iphdr));	
	eiph->optionid = 0x9a;
	eiph->option_length = 12;
	eiph->esp = 1;
	eiph->edp = 1;
	eiph->reserved = 0;
	eiph->extended_saddr=0xffffffff; 
	eiph->extended_daddr=esaddr; 

	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

	skb->mac_header = skb_push(skb, 14);
	ethdr = (struct ethhdr *) skb->mac_header; 
	memcpy(ethdr->h_dest, dmac, ETH_ALEN); 
	memcpy(ethdr->h_source, smac, ETH_ALEN); 
	ethdr->h_proto = __constant_htons(ETH_P_IP);

/***
	//skb_dst_set(skb, NULL); 
	//ip_route_output_slow 
	retval = ip_route_input_slow(skb, dip, sip, 224, dev);
	//printk("icmp_route_input_slow retval = %d\n", retval);
        rt = skb_rtable(skb);
        sk = icmp_sk(dev_net((rt)->dst.dev));
	printk("rt=%x sk=%x\n", rt,sk);
***/

	dev_queue_xmit(skb);
	//ip_queue_xmit(skb); or ip_push_pending_frames()
	goto success;
out:
	return -1;

success:
	return 0;

/*
*/
}

/**
 *  Packets headed towards destination on a locally connected LAN.
 */
unsigned int apply_eip_dnat(const struct net_device *in, struct sk_buff *skb)
{
	struct iphdr *iph = NULL;
	struct extended_ip *ipopt = NULL;

	if(!in){
		return NF_ACCEPT;	
	}
	
	iph = ip_hdr(skb);
	if(iph->ihl != 8){
		return NF_ACCEPT;
	}

	ipopt = (void *)skb->data + sizeof(struct iphdr); 
	if(!iph || !ipopt){ return NF_ACCEPT; }

	if(ipopt->optionid == EXTENDED_IP){
		if(iph->protocol == 1){
			int error = 0;
			error = sendpacket(iph->saddr, iph->daddr, ipopt->extended_saddr,
					                           ipopt->extended_daddr, "data", 4);
			if(error < 0){
				printk("sock_create failed\n");
				return NF_ACCEPT;	
			}

			
			return NF_STOLEN; //NF_ACCEPT
		}

	}

	return NF_ACCEPT;
}


static unsigned int
nf_eipnat_in(unsigned int hooknum,
	  struct sk_buff *skb,
	  const struct net_device *in,
	  const struct net_device *out,
	  int (*okfn)(struct sk_buff *))
{
	
	return nf_nat_fn("dnat in prerouting", hooknum, skb, in, out, okfn);
}


static struct nf_hook_ops nf_icmp_ops[] __read_mostly = {
	// Before packet filtering, change destination 
	{
		.hook		= nf_eipnat_in,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_NAT_DST,
	},
};


static int __init nf_extendedip_init(void)
{
	int ret = 0;

	write_lock_bh(&dev_base_lock);

	write_unlock_bh(&dev_base_lock);

	ret = nf_register_hooks(nf_icmp_ops, ARRAY_SIZE(nf_icmp_ops));
	if (ret < 0) {
		printk("couldn't register nf_icmp_ops\n");
		return -1;
	}
	printk("registered nf_icmp_ops\n");

	return 0;
}
module_init(nf_extendedip_init);

static void __exit nf_extendedip_exit(void)
{
	nf_unregister_hooks(nf_icmp_ops, ARRAY_SIZE(nf_icmp_ops));
	printk("unregistered nf_icmp_ops\n");
	return;
}
module_exit(nf_extendedip_exit);

