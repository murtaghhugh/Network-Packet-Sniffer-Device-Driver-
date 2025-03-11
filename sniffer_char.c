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
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/kfifo.h>
#include <linux/jiffies.h>
#include <linux/slab.h>

#define DEVICE_NAME "sniffer"
#define MAJOR_NUM 42          // Fixed major number
#define FIFO_SIZE 8192        // Total FIFO size in bytes
#define INFO_BUFFER_SIZE 256  // Maximum size per packet info string

// Map our "ioctl" to unlocked_ioctl for convenience
#define ioctl unlocked_ioctl

// Global mutex for shared data
static DEFINE_MUTEX(packet_lock);

// FIFO to store packet info bytes
static DECLARE_KFIFO(packet_fifo, char, FIFO_SIZE);

// Netfilter hook structure
static struct nf_hook_ops nfho;

// Wait queue to block read() until data is available in the FIFO
static DECLARE_WAIT_QUEUE_HEAD(packet_wait_queue);

// Rate limiter: capture one packet every 100ms
static unsigned long last_capture_jiffies = 0;

/*
 * capture_packet - Netfilter hook function
 * Intercepts TCP/UDP packets, formats a string with packet info, and pushes it into the FIFO.
 */
static unsigned int capture_packet(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *ip_hdr_ptr;
    char info[INFO_BUFFER_SIZE];
    size_t info_len;

    if (!skb)
        return NF_ACCEPT;

    ip_hdr_ptr = ip_hdr(skb);
    if ((ip_hdr_ptr->protocol == IPPROTO_TCP) ||
        (ip_hdr_ptr->protocol == IPPROTO_UDP)) {

        // Rate limiting: only capture one packet every 100ms (system was crashing otherwise)
        if (!time_after(jiffies, last_capture_jiffies + msecs_to_jiffies(100)))
            return NF_ACCEPT;
        last_capture_jiffies = jiffies;

        info_len = snprintf(info, INFO_BUFFER_SIZE,
            "Src: %pI4, Dst: %pI4, Proto: %d, Size: %u bytes\n",
            &ip_hdr_ptr->saddr, &ip_hdr_ptr->daddr,
            ip_hdr_ptr->protocol, skb->len);

        mutex_lock(&packet_lock);
        // Only add info if there's enough space in the FIFO
        if (kfifo_avail(&packet_fifo) >= info_len) {
            kfifo_in(&packet_fifo, info, info_len);
            wake_up_interruptible(&packet_wait_queue);
        } else {
            pr_info("sniffer: FIFO full, dropping packet info\n");
        }
        mutex_unlock(&packet_lock);

        if (ip_hdr_ptr->protocol == IPPROTO_TCP)
            pr_info("TCP packet captured, size: %u bytes\n", skb->len);
        else if (ip_hdr_ptr->protocol == IPPROTO_UDP)
            pr_info("UDP packet captured, size: %u bytes\n", skb->len);
    }
    return NF_ACCEPT;
}

//open
static int open(struct inode *inode, struct file *file)
{
    pr_info("sniffer: Device opened\n");
    return 0;
}

//close
static int close(struct inode *inode, struct file *file)
{
    pr_info("sniffer: Device closed\n");
    return 0;
}

/*
 * read - Reads data from the FIFO and copies it to userspace.
 * It blocks until data is available.
 */
static ssize_t read(struct file *file, char __user *buf, size_t len, loff_t *off)
{
    int ret;
    unsigned int available;
    char *temp_buf;

    // Block until the FIFO has data
    wait_event_interruptible(packet_wait_queue, !kfifo_is_empty(&packet_fifo));

    mutex_lock(&packet_lock);
    available = kfifo_len(&packet_fifo);
    ret = min(len, (size_t)available);
    // Allocate temporary buffer dynamically
    temp_buf = kmalloc(ret, GFP_KERNEL);
    if (!temp_buf) {
        mutex_unlock(&packet_lock);
        return -ENOMEM;
    }
    if (kfifo_out(&packet_fifo, temp_buf, ret) != ret) {
        kfree(temp_buf);
        mutex_unlock(&packet_lock);
        return -EFAULT;
    }
    mutex_unlock(&packet_lock);

    if (copy_to_user(buf, temp_buf, ret)) {
        kfree(temp_buf);
        return -EFAULT;
    }
    kfree(temp_buf);
    return ret;
}


static long ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    pr_info("sniffer ioctl: cmd=%u, arg=%lu\n", cmd, arg);
    return 0;
}


static struct file_operations fops = {
    .owner   = THIS_MODULE,
    .open    = open,
    .release = close,
    .read    = read,
    .ioctl   = ioctl,  
};

//registers everything
static int __init sniffer_init(void)
{
    int ret;

    ret = register_chrdev(MAJOR_NUM, DEVICE_NAME, &fops);
    if (ret < 0) {
        pr_err("sniffer: Failed to register chrdev with major %d\n", MAJOR_NUM);
        return ret;
    }

    INIT_KFIFO(packet_fifo);

    nfho.hook     = capture_packet;
    nfho.hooknum  = NF_INET_PRE_ROUTING;
    nfho.pf       = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    ret = nf_register_net_hook(&init_net, &nfho);
    if (ret < 0) {
        unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
        pr_err("sniffer: Failed to register netfilter hook\n");
        return ret;
    }

    pr_info("sniffer: Module loaded. Major number: %d\n", MAJOR_NUM);
    return 0;
}

static void __exit sniffer_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
    pr_info("sniffer: Module unloaded.\n");
}

module_init(sniffer_init);
module_exit(sniffer_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Block 3");
MODULE_DESCRIPTION("Packet Sniffer with FIFO (TCP/UDP only) and rate limiting");
