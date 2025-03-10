#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>

#define DEVICE_NAME "sniffer"
#define MAJOR_NUM 42  // Fixed major number

static DEFINE_MUTEX(packet_lock);
static char packet_data[1500];
static size_t packet_length = 0;
static bool packet_available = false;

/* Declare the hook ops globally */
static struct nf_hook_ops nfho;

/*
 * Netfilter hook function: Intercepts incoming IPv4 packets (TCP, UDP, ICMP)
 * and stores one packet in a global array.
 */
static unsigned int capture_packet(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *ip_header;

    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (ip_header->protocol == IPPROTO_TCP ||
        ip_header->protocol == IPPROTO_UDP ||
        ip_header->protocol == IPPROTO_ICMP) {

        mutex_lock(&packet_lock);
        packet_length = skb->len;
        if (packet_length > sizeof(packet_data))
            packet_length = sizeof(packet_data);
        skb_copy_bits(skb, 0, packet_data, packet_length);
        packet_available = true;
        mutex_unlock(&packet_lock);

        pr_info("Packet captured - Protocol: %u, Size: %zu bytes\n",
                ip_header->protocol, packet_length);
    }
    return NF_ACCEPT;
}

/*
 * Character device read, returns the stored packet to user space if available,
 * then clears it.
 */
static ssize_t sniffer_read(struct file *file, char __user *buf, size_t len, loff_t *off)
{
    int ret;

    mutex_lock(&packet_lock);
    if (!packet_available) {
        mutex_unlock(&packet_lock);
        return 0;  // No packet available; return EOF
    }
    ret = min(len, packet_length);
    if (copy_to_user(buf, packet_data, ret)) {
        mutex_unlock(&packet_lock);
        return -EFAULT;  // Failed to copy data to user space
    }
    packet_available = false;  // Mark packet as read
    mutex_unlock(&packet_lock);
    return ret;
}

/*
 * File operations structure.
 */
static struct file_operations sniffer_fops = {
    .owner = THIS_MODULE,
    .read  = sniffer_read,
};

/*
 * Module initialization: Registers the character device and Netfilter hook.
 */
static int __init sniffer_init(void)
{
    int ret;

    ret = register_chrdev(MAJOR_NUM, DEVICE_NAME, &sniffer_fops);
    if (ret < 0) {
        pr_err("Failed to register chrdev with major %d\n", MAJOR_NUM);
        return ret;
    }

    /* Initialize the global nf_hook_ops structure */
    nfho.hook = capture_packet;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &nfho);
    if (ret < 0) {
        unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
        pr_err("Failed to register netfilter hook\n");
        return ret;
    }

    pr_info("Packet Sniffer Loaded. Major number: %d\n", MAJOR_NUM);
    return 0;
}

/*
 * Module cleanup: Unregisters the Netfilter hook and the character device.
 */
static void __exit sniffer_exit(void)
{
    /* Unregister the hook using the global nf_hook_ops structure */
    nf_unregister_net_hook(&init_net, &nfho);
    unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
    pr_info("Packet Sniffer Unloaded.\n");
}

module_init(sniffer_init);
module_exit(sniffer_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Block 3");
MODULE_DESCRIPTION("Packet Sniffer");
