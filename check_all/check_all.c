#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops nfho;

unsigned int 
hook_func(void *priv,
          struct sk_buff *skb,
          const struct nf_hook_state *state
          ) {
    printk(KERN_ALERT "A packet is received!\n");
    return NF_ACCEPT;
}

static int __init
init_check(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(NULL, &nfho);

    return 0;
}

static void __exit
clean_check(void) {
    nf_unregister_net_hook(NULL, &nfho);
}

module_init(init_check);
module_exit(clean_check);
