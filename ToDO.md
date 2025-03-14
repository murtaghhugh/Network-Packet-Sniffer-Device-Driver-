
# TODO List for Network Packet Sniffer

## User Space
- [ ] Ensure proper separation between kernel space and user space.
- [ ] Implement a clear interface between the kernel module and user-space program.
- [ ] Test `ioctl` calls for setting filters and confirm successful packet capture.
- [ ] Ensure that the user-space program can handle all three filter modes:
    - [ ] TCP only
    - [ ] UDP only
    - [ ] Both TCP and UDP

---

## /proc Statistics
- [ ] Create a `/proc/sniffer_stats` file to store port usage statistics.
- [ ] Ensure that port usage counts are updated dynamically as packets are captured.
- [ ] Test `/proc/sniffer_stats` output using `cat` or `grep`.
- [ ] Confirm proper cleanup of `/proc` entries when the module is unloaded.

---

## Oisin's Advice
> **"Understand the code!"**  
- [ ] Paste slides and rubric into ChatGPT to clarify learning outcomes and deliverables.
- [ ] Take a full day to review module learning outcomes and deliverables.  
- [ ] Ensure deep understanding of how the code works internally.  
- [ ] Ensure you can explain every part of the code.  

---

## FIFO Algorithm
- [ ] Fully implement a FIFO-based buffer to store captured packets.
- [ ] Ensure that the buffer size is reasonable to prevent memory overflow.
- [ ] Ensure data is consumed in FIFO order.
- [ ] Test buffer overflow scenarios and confirm recovery.

---

## Stretch Goal
> **"Create a user-space program that reads from the device file."**  
- [ ] Write a user-space program that reads and processes packets from `/dev/sniffer`.  
- [ ] Test using:
```bash
cat /dev/sniffer | grep TCP
```
- [ ] Implement a way to parse and format output for easier readability.

---

## Understanding Your Own Code
- [ ] Review the module book, slides, and rubric for full understanding.  
- [ ] Ensure you understand how `ioctl`, `netfilter`, `FIFO`, and `/proc` work.  
- [ ] Ensure you can answer questions about module functionality and packet flow.  
- [ ] Understand kernel-to-user communication paths.

---

## Final Checklist Before Submission
- [ ] Test all filter modes (`TCP`, `UDP`, `Both`)  
- [ ] Confirm `dmesg` output shows correct filter mode and packet capture  
- [ ] Test `/proc/sniffer_stats` output and confirm it reflects accurate statistics  
- [ ] Confirm no memory leaks or crashes  
- [ ] Ensure clean loading and unloading of the module  
- [ ] Ensure clear and informative `README.md`  

---

 **Stay focused — you've got this!** 
