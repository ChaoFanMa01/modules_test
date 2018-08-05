#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>

static struct nf_hook_ops nfho;

static unsigned char *drop_ip = "\x7f\x00\x00\x01";

static unsigned int
hook_func(const struct nf_hook_ops *ops,
          struct sk_buff *skb,
          const struct net_device *in,
          const struct net_device *out,
          int (*okfn)(struct sk_buff *)) {
    struct iphdr *ih;
    unsigned char a0, a1, a2, a3;
    // Find IP header through offset.
    ih = (struct iphdr *)(skb->head + skb->network_header);
    a0 = ih->saddr & 0x000000ff;
    a1 = (ih->saddr & 0x0000ff00) >> 8;
    a2 = (ih->saddr & 0x00ff0000) >> 16;
    a3 = (ih->saddr & 0xff000000) >> 24;
    if (a0 == *drop_ip && a1 == *(drop_ip + 1) && 
        a2 == *(drop_ip + 2) && a3 == *(drop_ip + 3)) {
        printk(KERN_ALERT "Dropped packet from... %d.%d.%d.%d",
               *drop_ip, *(drop_ip + 1), *(drop_ip + 2),
               *(drop_ip + 3));
        return NF_DROP;
    } else {
        return NF_ACCEPT;
    }
}

static int __init
init_filter(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&nfho);

    return 0;
}

static void __exit
clean_filter(void) {
    nf_unregister_hook(&nfho);
}

module_init(init_filter);
module_exit(clean_filter);

MODULE_LICENSE("Dual BSD/GPL");
