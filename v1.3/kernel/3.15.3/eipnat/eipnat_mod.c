#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <net/ip.h>
#include <linux/inet.h>        ///for in_aton function to convert IP to number
#include  "eip.h"

MODULE_LICENSE("GPL");

#define RDTSCLL(val) do { \
     unsigned int __a,__d; \
     asm volatile("rdtsc" : "=a" (__a), "=d" (__d)); \
     (val) = ((unsigned long)__a) | (((unsigned long)__d)<<32); \
} while(0)

static char *masq_ip = "0.0.0.0";
static char *nic_name = "eth0";
unsigned int outside_ip;

module_param(masq_ip, charp, 0000);
MODULE_PARM_DESC(masq_ip, "A character string");
module_param(nic_name, charp, 0000);
MODULE_PARM_DESC(nic_name, "A character string");

unsigned int apply_eip_dnat(const struct net_device *, struct sk_buff *);
unsigned int apply_eip_snat(const struct net_device *, struct sk_buff *);
void calc_checksum(struct sk_buff *);
__wsum checksum_addH(void *, int );
__wsum checksum_addN(void *, int );
uint16_t checksum_final(__wsum );


static unsigned int pre_myhook_func(unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
	apply_eip_dnat(in, skb);

	return NF_ACCEPT;
}

static unsigned int post_myhook_func(unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;

    if (!skb) {
        printk(KERN_INFO "NULL sock buff header\n");
        return NF_ACCEPT;
    }

//    printk(KERN_INFO "SRC: %pI4 --> DST: %pI4\n",&(iph->saddr),&(iph->daddr));

    apply_eip_snat(out, skb);


    return NF_ACCEPT;
}

static struct nf_hook_ops myhook_ops[] __read_mostly = {
        // Before packet filtering, change destination
        {
                .hooknum        = NF_INET_PRE_ROUTING,
                .hook           = pre_myhook_func,
                .pf             = NFPROTO_IPV4,
                .priority       = 1,
        },
        // After packet filtering, change source
        {
                .hooknum        = NF_INET_POST_ROUTING,
                .hook           = post_myhook_func,
                .pf             = NFPROTO_IPV4,
                .priority       = 1,
        },
};

static int __init custom_init_module(void)
{
    int ret = 0;

      outside_ip = in_aton(masq_ip);
      if(outside_ip == 0){
                printk("Error: try 'insmod eipnat.ko masq_ip=\"1.1.1.1\"'\n");
                return -1;
      }

      printk("masq_ip = %s/%x\n", masq_ip, ntohl(outside_ip));
      printk("nic_name= %s\n", nic_name);

 
    ret = nf_register_hooks(myhook_ops, ARRAY_SIZE(myhook_ops));
    if(ret < 0){
	return -1;
    }

    printk(KERN_INFO "init_module() called\n");
    return 0;
}

static void __exit custom_cleanup_module(void)
{
    printk(KERN_INFO "cleanup_module() called\n");
    nf_unregister_hooks(myhook_ops, ARRAY_SIZE(myhook_ops));
}

module_init(custom_init_module);
module_exit(custom_cleanup_module);



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
	
	//printk("%x\n", dev_base);
	if(strcmp(in->name, nic_name) != 0){
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);
	if(iph->ihl != 8){
		return NF_ACCEPT;
	}

	ipopt = (void *)skb->data + sizeof(struct iphdr); 
	if(!iph || !ipopt){ return NF_ACCEPT; }

	if(ipopt->optionid == ENIP_MAGIC){
		newip      = ipopt->extended_daddr;

		iph->daddr = newip;   
		ipopt->extended_daddr = 0;
		ipopt->edp = 0;
	
		///if the packet was udp or tcp we 
		///have just messed up the checksum and need to
		///recompute it.  it is also necessary to update
		///the ip header checksum.

		calc_checksum(skb);
		printk("processed enip dnat packet\n");
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

/*
 * Packets headed towards the Internet, outside interface address placed
 * as source of packet.
 */
unsigned int apply_eip_snat(const struct net_device *out, struct sk_buff *skb)
{
	struct iphdr *iph = NULL;
	struct extended_ip *ipopt = NULL;

	//if(!out || strcmp(out->name, "eth0") != 0){

	if(!out || strcmp(out->name, nic_name) != 0){
		return NF_ACCEPT;
	}


	iph = ip_hdr(skb);
	if(!iph)
		return NF_ACCEPT;

	if(iph->ihl == 8){
	   //ipopt = (void *)skb->data + sizeof(struct iphdr);
	   ipopt = (char *)(skb->data + sizeof(struct iphdr));
	   if(ipopt->optionid == ENIP_MAGIC){
		ipopt->esp = 1;
		ipopt->extended_saddr = iph->saddr;
		iph->saddr = outside_ip;
		ipopt->esp = 1;
		iph->check = 0;
		calc_checksum(skb);
	   }
	}

	return NF_ACCEPT;
}

