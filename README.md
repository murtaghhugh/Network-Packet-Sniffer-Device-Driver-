Network Packet Sniffer Device Driver

A kernel-mode network packet sniffer that captures TCP and UDP packets using a character device interface.
🚀 1. Building the Module

To compile the module:

make clean
make

🏆 2. Load the Module

To insert the module into the kernel:

sudo insmod sniffer_char.ko

✅ Confirm the module has been loaded and check the assigned major number:

dmesg | grep sniffer

Example output:

[6948.101391] sniffer: Module loaded. Major number: 511

🖥️ 3. Create the Device File

Create the device file using the assigned major number:
(Replace 511 with the actual major number from dmesg)

sudo mknod /dev/sniffer c 511 0
sudo chmod 666 /dev/sniffer

🌐 4. Set Filters (TCP/UDP Capture)

You can control which packets to capture using the ioctl interface:
Filter Mode	Command	Description
All Packets	./sniffer_user 0	Capture both TCP and UDP
TCP Only	./sniffer_user 1	Capture TCP only
UDP Only	./sniffer_user 2	Capture UDP only

Example:

./sniffer_user 1

✅ Confirm that the filter is set:

dmesg | tail -10

Example output:

[7012.827946] sniffer: ioctl called with cmd=1074032641
[7012.827956] sniffer: Filter mode set to 1

📥 5. Read Captured Packets

You can read captured TCP/UDP packets from the FIFO buffer:
Option 1 — Use cat:

cat /dev/sniffer

Option 2 — Use dd:

dd if=/dev/sniffer bs=256 count=1

📊 6. Check Port Usage Statistics

Your module stores per-port packet counts in /proc:

cat /proc/sniffer_stats

Example output:

Port 443: 104 packets
Port 22:   5 packets

🧪 7. Test by Generating Traffic
✅ Ping Test

(For basic connectivity check — ICMP traffic won’t be captured)

ping -c 4 google.com

✅ Netcat Test (TCP)

    Start a Netcat listener:

nc -l -p 4444

    Send a message from another terminal:

echo "Hello" | nc 127.0.0.1 4444

✅ You should see the packet being captured:

[1741960225.471292] TCP Src: 127.0.0.1:5555 -> Dst: 127.0.0.1:4444

🧹 8. Unload the Module

To remove the module from the kernel:

sudo rmmod sniffer_char

✅ Confirm successful removal:

dmesg | tail -10

Example output:

[7050.567890] sniffer: Module unloaded.

🔎 9. Debugging and Troubleshooting
✅ Check Kernel Logs:

dmesg | tail -50

✅ Check System Logs:

sudo tail -f /var/log/syslog

✅ Ensure Device Exists:

ls -l /dev/sniffer

✅ Permissions Issue Fix:

If you get a permissions error, reset file permissions:

sudo chmod 666 /dev/sniffer

🎯 10. Optimize Performance (Optional)
✅ Increase FIFO Buffer Size

If the buffer is filling up too quickly, increase the FIFO size in sniffer_char.c:

#define FIFO_SIZE 32768

Then rebuild the module:

make clean
make

✅ 11. Make the Module Load at Boot (Optional)

    Copy the module to the kernel directory:

sudo cp sniffer_char.ko /lib/modules/$(uname -r)/kernel/drivers/misc/

    Load the module at boot:

echo "sniffer_char" | sudo tee -a /etc/modules

✅ 12. Clean Build Files

If you need to clean up:

make clean
