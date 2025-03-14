
# 🖥️ Network Packet Sniffer

![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)
![Kernel Version](https://img.shields.io/badge/Kernel-6.11.0-blue)
![License](https://img.shields.io/badge/License-GPLv2-red)

---

## 📖 Table of Contents
- [Building the Module](#building-the-module)
- [Load the Module](#load-the-module)
- [Create the Device File](#create-the-device-file)
- [Set Filters](#set-filters-tcpudp-capture)
- [Read Captured Packets](#read-captured-packets)
- [Check Port Usage Statistics](#check-port-usage-statistics)
- [Test by Generating Traffic](#test-by-generating-traffic)
- [Unload the Module](#unload-the-module)
- [Debugging and Troubleshooting](#debugging-and-troubleshooting)
- [Optimize Performance](#optimize-performance)
- [Make the Module Load at Boot](#make-the-module-load-at-boot)
- [Clean Build Files](#clean-build-files)

---

## 🚀 Building the Module
To compile the module:
```bash
make clean
make
```

---

## 🖥️ Load the Module
To insert the module into the kernel:
```bash
sudo insmod sniffer_char.ko
```

✅ Confirm the module has been loaded and check the assigned major number:
```bash
dmesg | grep sniffer
```
Example output:
```
[6948.101391] sniffer: Module loaded. Major number: 511
```

---

## 🌐 Create the Device File
Create the device file using the assigned major number:  
(Replace `511` with the actual major number from `dmesg`)
```bash
sudo mknod /dev/sniffer c 511 0
sudo chmod 666 /dev/sniffer
```

---

## 🌐 Set Filters (TCP/UDP Capture)
You can control which packets to capture using the `ioctl` interface:

| Filter Mode | Command | Description |
|------------|---------|-------------|
| **All Packets** | `./sniffer_user 0` | Capture both TCP and UDP |
| **TCP Only**     | `./sniffer_user 1` | Capture TCP only |
| **UDP Only**     | `./sniffer_user 2` | Capture UDP only |

Example:
```bash
./sniffer_user 1
```

✅ Confirm that the filter is set:
```bash
dmesg | tail -10
```
Example output:
```
[7012.827946] sniffer: ioctl called with cmd=1074032641
[7012.827956] sniffer: Filter mode set to 1
```

---

## 📥 Read Captured Packets
You can read captured TCP/UDP packets from the FIFO buffer:

### Option 1 — Use `cat`:
```bash
cat /dev/sniffer
```

### Option 2 — Use `dd`:
```bash
dd if=/dev/sniffer bs=256 count=1
```

---

## 📊 Check Port Usage Statistics
Your module stores per-port packet counts in `/proc`:

```bash
cat /proc/sniffer_stats
```

Example output:
```
Port 443: 104 packets
Port 22:   5 packets
```

---

## 🧪 Test by Generating Traffic
### ✅ Ping Test  
(For basic connectivity check — ICMP traffic won’t be captured)
```bash
ping -c 4 google.com
```

### ✅ Netcat Test (TCP)  
1. Start a Netcat listener:
```bash
nc -l -p 4444
```
2. Send a message from another terminal:
```bash
echo "Hello" | nc 127.0.0.1 4444
```

✅ You should see the packet being captured:
```
[1741960225.471292] TCP Src: 127.0.0.1:5555 -> Dst: 127.0.0.1:4444
```

---

## ✅ Unload the Module
To remove the module from the kernel:
```bash
sudo rmmod sniffer_char
```

✅ Confirm successful removal:
```bash
dmesg | tail -10
```
Example output:
```
[7050.567890] sniffer: Module unloaded.
```

---

<details>
  <summary>🔎 Debugging and Troubleshooting</summary>
  
  - **Check Kernel Logs:**  
  ```bash
  dmesg | tail -50
  ```

  - **Check System Logs:**  
  ```bash
  sudo tail -f /var/log/syslog
  ```

  - **Ensure Device Exists:**  
  ```bash
  ls -l /dev/sniffer
  ```

  - **Permissions Issue Fix:**  
  If you get a permissions error, reset file permissions:  
  ```bash
  sudo chmod 666 /dev/sniffer
  ```

</details>

---

## 🚀 Optimize Performance (Optional)
### ✅ Increase FIFO Buffer Size  
If the buffer is filling up too quickly, increase the FIFO size in `sniffer_char.c`:
```c
#define FIFO_SIZE 32768
```
Then rebuild the module:
```bash
make clean
make
```

---

## 📂 Make the Module Load at Boot (Optional)
1. Copy the module to the kernel directory:
```bash
sudo cp sniffer_char.ko /lib/modules/$(uname -r)/kernel/drivers/misc/
```

2. Load the module at boot:
```bash
echo "sniffer_char" | sudo tee -a /etc/modules
```

---

## 🧹 Clean Build Files
If you need to clean up:
```bash
make clean
```

---

## 🎉 DONE!  
You now have a fully functional packet sniffer. The module is dynamically assigned a major number, captures TCP/UDP packets using FIFO, and filters them based on `ioctl` settings. 🔥

---

## 🚀 Pro Tips for Better Performance  
✅ Increase FIFO size for high-traffic environments  
✅ Filter out low-priority traffic using `iptables`  
✅ Write a script to auto-load the module and set filters at boot  

---

🔥 **Now Go Capture Some Packets!** 😎
