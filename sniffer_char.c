// =====================================
// Include Headers
// =====================================

// Core Kernel
#include <linux/module.h>                   // Load and Unload the Kernel Modules
#include <linux/kernel.h>                   // Kernel Logging and General Utilites

// Networking 
#include <linux/netfilter.h>                // Net-filter -> Packet Capture
#include <linux/netfilter_ipv4.h>           // IPv4 Packet Capture
#include <linux/ip.h>                       // Working with IP Headers
#include <linux/tcp.h>                      // Working with TCP Headers
#include <linux/udp.h>                      // Working with UDP Headers

// Filesystem & Character Device Headers
#include <linux/fs.h>                       // File Operations -> (create, read, write)
#include <linux/proc_fs.h>                  // Creates entries in /proc

// Synchronisation & Scheduling
#include <linux/mutex.h>                    // Mutual Exclusion to Protect Shared Resources
#include <linux/wait.h>                     // Wait Queues -> Sleeping & Waking processes
#include <linux/sched.h>                    // Scheduling -> Process Managment

// FIFO Managment
#include <linux/kfifo.h>                    // FIFO Buffer

// Jiffies & Timmings
#include <linux/jiffies.h>                  // Kernel Timing Functions
#include <linux/timekeeping.h>              // Gets Timestamps

// Memory Managment & User-Space Access
#include <linux/slab.h>                     // Kernel Memory Allocation
#include <linux/uaccess.h>                  // User-Kernel Memory Access 


// =====================================
// Definitions and Constants
// =====================================

#define DEVICE_NAME "Network Packet Sniffer"
#define FIFO_SIZE 8192
#define INFO_BUFFER_SIZE 256    // Size of Packets in Buffer
#define SNIFFER_SET_FILTER _IOW('p', 1, int)    // IOCTL Command for Filter 

// Function prototypes
static long sniffer_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

// Global variable to stop the loop on signal (must be volatile because it’s accessed by a signal handler)
volatile int stop = 0;


// =====================================
// Global Variables
// =====================================

static DEFINE_MUTEX(packet_lock); // Protect Access to Shared Data

// Two FIFO Buffers
static DECLARE_KFIFO(tcp_fifo, char, FIFO_SIZE); 
static DECLARE_KFIFO(udp_fifo, char, FIFO_SIZE);

// Wait Queues for new Data
static DECLARE_WAIT_QUEUE_HEAD(tcp_wait_queue);
static DECLARE_WAIT_QUEUE_HEAD(udp_wait_queue);

static struct nf_hook_ops nfho; // Net-Filter Hook 
static unsigned int port_usage[65536] = {0}; // Array to Track No. of Packets per Port
static int filter_mode = 0; // Filter Mode off Packets Received 
static int major_num = 0; // Major No. for the Character Device 

static struct proc_dir_entry *proc_entry; // /proc/sniffer_statsnan



// =====================================
// Capture Packet Logic
// =====================================

/**
 * capture_packet - Captures TCP and UDP packets using Netfilter.
 *
 * @priv:    Private data passed from the netfilter framework.
 * @skb:     Socket buffer containing the packet.
 * @state:   Netfilter state.
 *
 * Captures incoming packets, filters them based on user-defined settings,
 * and stores them in the appropriate FIFO buffer.
 *
 * Return: NF_ACCEPT to allow the packet through.
 */
static unsigned int capture_packet(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

    struct iphdr *ip_hdr_ptr;   // Pointer to IP header within the packet
    struct tcphdr *tcp_header;  // Pointer to TCP header (if TCP packet)
    struct udphdr *udp_header;  // Pointer to UDP header (if UDP packet)
    struct timespec64 ts;
    char info[INFO_BUFFER_SIZE];
    size_t info_len;
    static unsigned long last_jiffies = 0;

    // Rate limiting: 10 packets per second
    if (time_after(jiffies, last_jiffies + msecs_to_jiffies(100))) {
        last_jiffies = jiffies;
    } else {
        return NF_ACCEPT;
    }

    if (!skb) return NF_ACCEPT;

    // Get current timestamp
    ktime_get_real_ts64(&ts);
    ip_hdr_ptr = ip_hdr(skb);

    if (ip_hdr_ptr->protocol == IPPROTO_TCP || ip_hdr_ptr->protocol == IPPROTO_UDP) {
        if (filter_mode == 1 && ip_hdr_ptr->protocol == IPPROTO_UDP) return NF_ACCEPT;
        if (filter_mode == 2 && ip_hdr_ptr->protocol == IPPROTO_TCP) return NF_ACCEPT;

        if (!mutex_trylock(&packet_lock)) return NF_ACCEPT;

        if (ip_hdr_ptr->protocol == IPPROTO_TCP) {
            tcp_header = tcp_hdr(skb);
            port_usage[ntohs(tcp_header->source)]++;

            info_len = snprintf(info, INFO_BUFFER_SIZE,
                "[%lld.%.6ld] TCP Src: %pI4:%u -> Dst: %pI4:%u\n",
                ts.tv_sec, ts.tv_nsec / 1000,
                &ip_hdr_ptr->saddr, ntohs(tcp_header->source),
                &ip_hdr_ptr->daddr, ntohs(tcp_header->dest));

            if (kfifo_avail(&tcp_fifo) >= info_len) {
                kfifo_in(&tcp_fifo, info, info_len);
                wake_up_interruptible(&tcp_wait_queue);
            }
        } else {
            udp_header = udp_hdr(skb);
            port_usage[ntohs(udp_header->dest)]++;

            info_len = snprintf(info, INFO_BUFFER_SIZE,
                "[%lld.%.6ld] UDP Src: %pI4:%u -> Dst: %pI4:%u\n",
                ts.tv_sec, ts.tv_nsec / 1000,
                &ip_hdr_ptr->saddr, ntohs(udp_header->source),
                &ip_hdr_ptr->daddr, ntohs(udp_header->dest));

            if (kfifo_avail(&udp_fifo) >= info_len) {
                kfifo_in(&udp_fifo, info, info_len);
                wake_up_interruptible(&udp_wait_queue);
            }
        }

        mutex_unlock(&packet_lock);
    }

    return NF_ACCEPT;
}


// =====================================
// Read Captured Packets (FIFO)
// =====================================

/**
 * sniffer_read - Reads packets from FIFO buffer.
 *
 * @file: File descriptor.
 * @buf: Buffer to store read data.
 * @len: Length of data to read.
 * @off: File offset.
 *
 * Return: Number of bytes read or error code.
 */
static ssize_t sniffer_read(struct file *file, char __user *buf, size_t len, loff_t *off) {
    int ret;
    char *temp_buf;

    if (len > FIFO_SIZE) return -EINVAL;

    temp_buf = kmalloc(len, GFP_KERNEL);
    if (!temp_buf) return -ENOMEM;

    if (filter_mode == 1 || filter_mode == 0) {
        if (wait_event_interruptible(tcp_wait_queue, kfifo_len(&tcp_fifo) > 0)) {
            kfree(temp_buf);
            return -ERESTARTSYS;
        }
        mutex_lock(&packet_lock);
        ret = kfifo_out(&tcp_fifo, temp_buf, len);
        mutex_unlock(&packet_lock);
        if (ret > 0) goto copy_to_user;
    }

    if (filter_mode == 2 || filter_mode == 0) {
        if (wait_event_interruptible(udp_wait_queue, kfifo_len(&udp_fifo) > 0)) {
            kfree(temp_buf);
            return -ERESTARTSYS;
        }
        mutex_lock(&packet_lock);
        ret = kfifo_out(&udp_fifo, temp_buf, len);
        mutex_unlock(&packet_lock);
        if (ret > 0) goto copy_to_user;
    }

    kfree(temp_buf);
    return 0;

copy_to_user:
    if (copy_to_user(buf, temp_buf, ret)) {
        kfree(temp_buf);
        return -EFAULT;
    }

    kfree(temp_buf);
    return ret;
}

/// =====================================
// Read Sniffer Statistics
// =====================================

static ssize_t proc_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) { //his function gets called when a user reads /proc/sniffer_stats
    char buf[256];
    int len; //Will store the length of the formatted string.

    if (*ppos > 0 || count < 256) return 0; // Stop reading after first call    

    len = snprintf(buf, sizeof(buf), //snprintf returns number of characters in string, len = this number.
        "Filter Mode: %d\n" 
        "Port 80:\nTCP Packets: %u\nUDP Packets: %u\n\n"
        "Port 53:\nTCP Packets: %u\nUDP Packets: %u\n",
        filter_mode, 
        (unsigned int)port_usage[80], (unsigned int)port_usage[80], 
        (unsigned int)port_usage[53], (unsigned int)port_usage[53]); 

    if (copy_to_user(ubuf, buf, len)) return -EFAULT; //moves data from buf(kernal space) to ubuf(user space)
                                                      //if copy_to_user fails, return -EFAULT (error : bad memory access)

    *ppos = len;        //updates file position so the next read starts from end
    return len;        //how many bytes were actually written
}

static const struct proc_ops proc_fops = {
    .proc_read = proc_read, // Call our function when reading /proc/sniffer_stats
};


// =====================================
// IOCTL Logic
// =====================================

static long sniffer_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int mode;

    if (cmd == SNIFFER_SET_FILTER) {
        if (copy_from_user(&mode, (int __user *)arg, sizeof(mode)))
            return -EFAULT;
        if (mode < 0 || mode > 2) return -EINVAL;
        filter_mode = mode;
        printk(KERN_INFO "sniffer: Filter mode set to %d\n", filter_mode);
        return 0;
    }

    return -ENOTTY;
}


// =====================================
// File Operations
// =====================================

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = sniffer_read,
    .unlocked_ioctl = sniffer_ioctl,
};


// =====================================
// Module Initialization
// =====================================

static int __init sniffer_init(void) {
    
    //#define major_num 240 //Tried to get the system to do it dynamically but have been unable to do it with the /proc code as of now - might have gotten it to work
    int ret;

    major_num = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_num < 0) {
        printk(KERN_ERR "sniffer: Failed to register character device. Error: %d\n", major_num);
        return major_num;
    } else {
        printk(KERN_INFO "sniffer: Device registered with major number: %d\n", major_num);
    }



    nfho.hook = capture_packet;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &nfho);
    if (ret < 0) {
        unregister_chrdev(major_num, DEVICE_NAME);
        return ret;
    }
    
    proc_entry = proc_create("sniffer_stats", 0666, NULL, &proc_fops);
    if (!proc_entry) {
        printk(KERN_ERR "sniffer: Failed to create /proc/sniffer_stats\n");

        // Cleanup previously registered components if proc creation fails
        nf_unregister_net_hook(&init_net, &nfho);
        unregister_chrdev(major_num, DEVICE_NAME);
        return -ENOMEM;
    }

    printk(KERN_INFO "sniffer: /proc/sniffer_stats created successfully.\n");

    printk(KERN_INFO "sniffer: Module loaded. Major number: %d\n", major_num);
    return 0;

    }



// =====================================
// Module Cleanup
// =====================================

static void __exit sniffer_exit(void) {
proc_remove(proc_entry);  // Remove /proc/sniffer_stats
    nf_unregister_net_hook(&init_net, &nfho);
    unregister_chrdev(major_num, DEVICE_NAME);
    printk(KERN_INFO "sniffer: Module unloaded\n");
}

module_init(sniffer_init);
module_exit(sniffer_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hugh Murtagh: 24421448, Daniel Tyutyunkov: 24417173, Roise McInerney: 24433802");
MODULE_DESCRIPTION("Packet Sniffer with FIFO and IOCTL");
