#include <linux/init.h>      // For module_init, module_exit
#include <linux/module.h>    // For THIS_MODULE, MODULE_LICENSE, etc.
#include <linux/fs.h>        // For register_chrdev, unregister_chrdev
#include <linux/uaccess.h>   // For copy_to_user, copy_from_user (if needed)

#define MY_MAJOR 42       // The Major number 
#define MYDRV_NAME "mydriver"  // Name 

// simple open just returning 0 for now
static int mydriver_open(struct inode *inode, struct file *file)
{
    pr_info("mydriver: device opened\n");
    return 0; // success
}

// Simple release that prints a message
static int mydriver_release(struct inode *inode, struct file *file)
{
    pr_info("mydriver: device closed\n");
    return 0; // success
}


static ssize_t mydriver_read(struct file *file, char __user *buf,
                             size_t len, loff_t *ppos)
{
    pr_info("mydriver: read called, returning 0\n");
    return 0; // 0 = EOF/no data
}

// Define file operations
static struct file_operations mydriver_fops = {
    .owner   = THIS_MODULE,
    .open    = mydriver_open,
    .read    = mydriver_read,
    .release = mydriver_release,
};

// Called when the module is loaded
static int __init mydriver_init(void)
{
    int ret;

    pr_info("mydriver: loading module...\n");

    // Register this driver with a fixed major number (42)
    ret = register_chrdev(MY_MAJOR, MYDRV_NAME, &mydriver_fops);
    if (ret < 0) {
        pr_err("mydriver: failed to register_chrdev on major %d\n", MY_MAJOR);
        return ret;
    }

    pr_info("mydriver: registered on major=%d\n", MY_MAJOR);
    pr_info("mydriver: module loaded\n");
    return 0; // success
}

// Called when the module is unloaded
static void __exit mydriver_exit(void)
{
    pr_info("mydriver: unloading module...\n");
    // Unregister from the kernel
    unregister_chrdev(MY_MAJOR, MYDRV_NAME);
    pr_info("mydriver: module unloaded\n");
}

module_init(mydriver_init);
module_exit(mydriver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Example driver using register_chrdev()");
