# Network-Packet-Sniffer-Device-Driver- 

Usage Guide:

1. " make "

2. " sudo insmod sniffer_char.ko "

3. " dmesg | grep -i sniffer  " look for Major Number Module loaded. Major number: 42=could be anything

4. Once you have compiled and inserted your packet sniffer kernel module, you can interact with it using **character device file operations** and **proc filesystem**. Here’s how you can do it:

5. "  sudo mknod /dev/sniffer c 42=<Major Number from step 3.> 0 "
6. "  sudo chmod 666 /dev/sniffer  "

## **3. Read Captured Packets**
You can read the intercepted TCP/UDP packets from the FIFO buffer.

cat /dev/sniffer

dd if=/dev/sniffer bs=256 count=1

If your module is filtering TCP or UDP packets, ensure your machine is generating some network traffic.


## **4. Set Filters (Enable TCP or UDP Capture)**
Your module has an **IOCTL interface** to set filters.

- **Enable TCP-only mode:**
  echo 1 | sudo tee /proc/sniffer_filter

- **Enable UDP-only mode:**
  echo 2 | sudo tee /proc/sniffer_filter

- **Capture both TCP and UDP:**
  echo 0 | sudo tee /proc/sniffer_filter

## **5. Check Port Usage Statistics**
Your module writes per-port packet counts to the `/proc` filesystem.

cat /proc/sniffer_stats

## **6. Unload the Module**
When you're done, unload the module safely:

sudo rmmod char_sniffer

Check `dmesg` for logs to confirm proper cleanup.

---

## **7. Debugging**
If the module is not working as expected:
- Check kernel logs:
  ```sh
  dmesg | tail -50
  ```
- Look at `/var/log/syslog`:
  ```sh
  sudo tail -f /var/log/syslog
  ```
- Ensure the device file exists:
  ```sh
  ls -l /dev/sniffer
  ```

---

### **Test by Generating Traffic**
To see your sniffer in action, generate network traffic:
- **Ping example (ICMP traffic won’t be captured, but useful for testing)**:
  ```sh
  ping -c 4 google.com
  ```
- **Start a simple netcat server and send a TCP message:**
  ```sh
  nc -l -p 4444   # Run this in one terminal
  echo "Hello" | nc 127.0.0.1 4444  # Run this in another
  ```

Your packet sniffer should capture details about TCP connections.

TA-Comments, Ensure that your Device/Mechainsism fpr storing web data employs a FIFO algorythim or similar, so that the collected metrics dont fill up the whole system.  
