---
title: "Python Black Hat：网络与安全脚本编程"
description: "涵盖套接字编程、Scapy数据包操作、HTTP请求和端口扫描的Python安全脚本速查表。渗透测试人员和安全研究人员必备的代码片段。"
date: 2026-02-10
tags: ["python", "cheatsheet", "penetration-testing", "security", "scripting"]
keywords: ["Python套接字编程", "Scapy速查表", "requests库Python", "Python黑客脚本", "Python端口扫描器", "Python网络安全", "Python渗透测试", "Scapy数据包构造", "Python反向Shell", "Python安全自动化"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python Black Hat：网络与安全脚本编程",
    "description": "用于网络安全、套接字编程、Scapy数据包操作和HTTP请求的必备Python脚本。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "zh-CN"
  }
---

## 系统初始化

Python是攻击性安全领域的通用语言。其可读的语法、丰富的标准库和强大的第三方包使其成为渗透测试人员、红队成员和安全研究人员的首选工具，用于自动化侦察、构建自定义漏洞利用程序和开发网络工具。从原始套接字编程到Scapy数据包操作，再到使用Requests进行Web应用测试，Python让您完全控制网络堆栈的每一层。本实战手册包含了最常见安全脚本任务的经过实战验证的代码片段——随时可以复制、修改并在授权的任务中部署。

所有脚本仅用于授权的安全测试和教育目的。

---

## 套接字网络编程

`socket`模块提供了Python中的低级网络接口。它允许直接访问TCP和UDP通信，使您能够从零开始构建自定义客户端、服务器、端口扫描器和网络工具。理解套接字是基础——每个更高级别的网络库都构建在套接字之上。

### TCP客户端

与远程主机建立连接并交换数据。

```python
import socket

target_host = "www.google.com"
target_port = 80

# Create a socket object (IPv4, TCP)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the target
client.connect((target_host, target_port))

# Send some data (HTTP GET request)
client.send(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")

# Receive the response
response = client.recv(4096)

print(response.decode())
client.close()
```

### UDP客户端

通过UDP（无连接协议）发送数据。

```python
import socket

target_host = "127.0.0.1"
target_port = 9999

# Create a UDP socket
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Send data (no connection needed)
client.sendto(b"AAABBBCCC", (target_host, target_port))

# Receive data
data, addr = client.recvfrom(4096)
print(data.decode())
client.close()
```

### TCP服务器

监听传入连接并在单独的线程中处理客户端。

```python
import socket
import threading

bind_ip = "0.0.0.0"
bind_port = 9999

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((bind_ip, bind_port))
server.listen(5)

print(f"[*] Listening on {bind_ip}:{bind_port}")

def handle_client(client_socket):
    request = client_socket.recv(1024)
    print(f"[*] Received: {request.decode()}")
    client_socket.send(b"ACK!")
    client_socket.close()

while True:
    client, addr = server.accept()
    print(f"[*] Accepted connection from: {addr[0]}:{addr[1]}")
    client_handler = threading.Thread(target=handle_client, args=(client,))
    client_handler.start()
```

---

## Scapy数据包操作

Scapy是Python中用于数据包构造、嗅探和网络发现的终极工具。它允许您逐层构建数据包、在网络上发送、捕获响应并分析流量——全部在Python脚本中完成。使用`pip install scapy`安装。

### 数据包嗅探

在网络接口上捕获实时流量。

```python
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Sniff 10 packets on the default interface
sniff(prn=packet_callback, count=10, store=0)
```

### 构造和发送数据包（ICMP Ping）

构建自定义ICMP回显请求并发送。

```python
from scapy.all import IP, ICMP, send, sr1

# Create and send an ICMP packet
packet = IP(dst="8.8.8.8") / ICMP()
send(packet)

# Send and wait for a response
response = sr1(packet, timeout=2, verbose=0)
if response:
    print(f"Reply from {response.src}: TTL={response.ttl}")
```

### ARP扫描器（网络发现）

使用ARP请求发现本地网络上的所有活动主机。

```python
from scapy.all import ARP, Ether, srp

target_ip = "192.168.1.0/24"

# Create ARP request packet
arp = ARP(pdst=target_ip)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether / arp

# Send and receive responses
result = srp(packet, timeout=3, verbose=0)[0]

print("IP Address\t\tMAC Address")
print("-" * 40)
for sent, received in result:
    print(f"{received.psrc}\t\t{received.hwsrc}")
```

### TCP SYN扫描（隐蔽端口扫描）

手动构造SYN数据包以在不完成握手的情况下检测开放端口。

```python
from scapy.all import IP, TCP, sr1, send

target_ip = "192.168.1.1"
target_port = 80

# Send SYN packet (flags="S")
packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
response = sr1(packet, timeout=1, verbose=0)

if response:
    if response[TCP].flags == 0x12:  # SYN-ACK
        print(f"Port {target_port} is OPEN")
        # Send RST to close connection cleanly
        send(IP(dst=target_ip) / TCP(dport=target_port, flags="R"), verbose=0)
    elif response[TCP].flags == 0x14:  # RST-ACK
        print(f"Port {target_port} is CLOSED")
else:
    print(f"Port {target_port} is FILTERED (no response)")
```

---

## HTTP请求（安全上下文）

`requests`库简化了Web应用测试、API模糊测试和自动化侦察的HTTP通信。使用`pip install requests`安装。

### 带自定义头部的GET请求

通过伪造头部绕过基本的WAF规则或指纹过滤器。

```python
import requests

url = "http://target-site.com"
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Cookie": "session_id=12345abcdef",
    "X-Forwarded-For": "127.0.0.1"
}

response = requests.get(url, headers=headers, timeout=10)
print(f"Status: {response.status_code}")
print(f"Server: {response.headers.get('Server', 'unknown')}")
```

### POST请求（登录暴力破解）

对登录表单的自动化凭据测试。

```python
import requests

target_url = "http://target-site.com/login"
usernames = ["admin", "root", "user"]
passwords = ["123456", "password", "admin123"]

for user in usernames:
    for pwd in passwords:
        data = {"username": user, "password": pwd}
        r = requests.post(target_url, data=data, timeout=10)

        if "Login failed" not in r.text:
            print(f"[+] Valid credentials: {user}:{pwd}")
            break
```

### 目录暴力破解

发现Web服务器上的隐藏路径和文件。

```python
import requests

target = "http://target-site.com"
wordlist = [
    "admin", "login", "dashboard", "api", "config",
    "backup", "uploads", "db", ".env", "robots.txt"
]

for word in wordlist:
    url = f"{target}/{word}"
    r = requests.get(url, timeout=5)
    if r.status_code != 404:
        print(f"[{r.status_code}] {url}")
```

---

## 简单端口扫描器

使用标准库套接字和线程的多线程TCP端口扫描器。通过将工作分配到多个线程来快速扫描前1024个端口。

```python
import socket
import threading
from queue import Queue

target = "192.168.1.1"
queue = Queue()
open_ports = []
print_lock = threading.Lock()

def portscan(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            return True
        return False
    except Exception:
        return False

def worker():
    while not queue.empty():
        port = queue.get()
        if portscan(port):
            with print_lock:
                print(f"[+] Port {port} is open")
                open_ports.append(port)
        queue.task_done()

# Fill the queue with ports 1-1024
for port in range(1, 1025):
    queue.put(port)

# Launch threads
thread_list = []
for _ in range(100):
    t = threading.Thread(target=worker, daemon=True)
    thread_list.append(t)
    t.start()

queue.join()
print(f"\n[*] Open ports: {open_ports}")
```

---

## 横幅抓取（Banner Grabbing）

通过读取开放端口上运行的服务的横幅来识别它们。

```python
import socket

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception:
        return None

target = "192.168.1.1"
ports = [21, 22, 25, 80, 443, 8080]

for port in ports:
    banner = grab_banner(target, port)
    if banner:
        print(f"[+] {target}:{port} — {banner}")
```
