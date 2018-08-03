#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("Dual BSD/GPL");

static struct nf_hook_ops nfho;

unsigned int 
hook_func(const struct nf_hook_ops *ops,
          struct sk_buff *skb,
          const struct net_device *in,
	  const struct net_device *out,
	  int (*okfn)(struct sk_buff *)
          ) {
    printk(KERN_ALERT "A packet is received!\n");
    return NF_ACCEPT;
}

static int __init
init_check(void) {
    nfho.hook = hook_func;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
// At the first time, the following statement is used:
//  nfho.hooknum = NF_IP_PRE_ROUTING;
// However, the compiler complains that NF_IP_PRE_ROUTING
// is not declared. This is because NF_IP_PRE_ROUTING is a
// user-space macro. When build a module in kernel, the 
// macro NF_INET_PRE_ROUTING is used as follows.
    nfho.hooknum = NF_INET_PRE_ROUTING;

    nf_register_hook(&nfho);

    return 0;
}

static void __exit
clean_check(void) {
    nf_unregister_hook(&nfho);
}

module_init(init_check);
module_exit(clean_check);
