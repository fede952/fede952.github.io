---
title: "Python Black Hat: برمجة الشبكات والأمن"
description: "ورقة مرجعية لبرمجة Python الأمنية تغطي برمجة المقابس، معالجة الحزم باستخدام Scapy، طلبات HTTP، ومسح المنافذ. مقتطفات كود أساسية لمختبري الاختراق والباحثين الأمنيين."
date: 2026-02-10
tags: ["python", "cheatsheet", "penetration-testing", "security", "scripting"]
keywords: ["برمجة المقابس Python", "ورقة مرجعية Scapy", "مكتبة requests Python", "سكربتات اختراق Python", "ماسح المنافذ Python", "أمن الشبكات Python", "اختبار الاختراق Python", "صناعة الحزم Scapy", "الصدفة العكسية Python", "أتمتة الأمن Python"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python Black Hat: برمجة الشبكات والأمن",
    "description": "سكربتات Python أساسية لأمن الشبكات وبرمجة المقابس ومعالجة الحزم باستخدام Scapy وطلبات HTTP.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ar"
  }
---

## تهيئة النظام

Python هي اللغة المشتركة للأمن الهجومي. بناء جملتها القابل للقراءة، ومكتبتها القياسية الواسعة، وحزمها القوية من الأطراف الثالثة تجعلها الأداة المفضلة لمختبري الاختراق وأعضاء الفريق الأحمر والباحثين الأمنيين الذين يحتاجون إلى أتمتة الاستطلاع وإنشاء ثغرات مخصصة وبناء أدوات شبكية. من برمجة المقابس الخام إلى معالجة الحزم باستخدام Scapy إلى اختبار تطبيقات الويب باستخدام Requests، يمنحك Python التحكم الكامل في كل طبقة من مكدس الشبكة. يحتوي هذا الدليل الميداني على مقتطفات كود مُجربة في المعارك لمهام البرمجة الأمنية الأكثر شيوعًا — جاهزة للنسخ والتكييف والنشر أثناء المهام المصرح بها.

جميع السكربتات مخصصة فقط لاختبارات الأمان المصرح بها والأغراض التعليمية.

---

## شبكات المقابس

توفر وحدة `socket` واجهة الشبكات منخفضة المستوى في Python. تمنحك وصولاً مباشراً إلى اتصالات TCP وUDP، مما يتيح لك بناء عملاء مخصصين وخوادم وماسحات منافذ وأدوات شبكية من الصفر. فهم المقابس أمر أساسي — كل مكتبة شبكات عالية المستوى مبنية فوقها.

### عميل TCP

إنشاء اتصال بمضيف بعيد وتبادل البيانات.

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

### عميل UDP

إرسال البيانات عبر UDP (بروتوكول بدون اتصال).

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

### خادم TCP

الاستماع للاتصالات الواردة ومعالجة العملاء في خيوط منفصلة.

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

## معالجة الحزم باستخدام Scapy

Scapy هي الأداة المثلى لصناعة الحزم والتنصت واكتشاف الشبكات في Python. تتيح لك بناء الحزم طبقة بطبقة وإرسالها عبر الشبكة والتقاط الاستجابات وتحليل حركة المرور — كل ذلك من سكربت Python. التثبيت باستخدام `pip install scapy`.

### التنصت على الحزم

التقاط حركة المرور المباشرة على واجهة شبكية.

```python
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Sniff 10 packets on the default interface
sniff(prn=packet_callback, count=10, store=0)
```

### صناعة وإرسال الحزم (Ping ICMP)

بناء طلب صدى ICMP مخصص وإرساله.

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

### ماسح ARP (اكتشاف الشبكة)

اكتشاف جميع المضيفين النشطين على شبكة محلية باستخدام طلبات ARP.

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

### مسح TCP SYN (مسح المنافذ الخفي)

صناعة حزم SYN يدوياً لاكتشاف المنافذ المفتوحة دون إكمال المصافحة.

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

## طلبات HTTP (سياق أمني)

مكتبة `requests` تبسط اتصالات HTTP لاختبار تطبيقات الويب وفحص واجهات API والاستطلاع الآلي. التثبيت باستخدام `pip install requests`.

### طلبات GET مع رؤوس مخصصة

تجاوز قواعد WAF الأساسية أو مرشحات البصمات عن طريق تزوير الرؤوس.

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

### طلب POST (هجوم القوة الغاشمة لتسجيل الدخول)

اختبار آلي لبيانات الاعتماد ضد نموذج تسجيل الدخول.

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

### القوة الغاشمة للمجلدات

اكتشاف المسارات والملفات المخفية على خادم ويب.

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

## ماسح منافذ بسيط

ماسح منافذ TCP متعدد الخيوط يستخدم المقابس وخيوط المعالجة من المكتبة القياسية. يمسح أول 1024 منفذاً بسرعة عن طريق توزيع العمل على خيوط متعددة.

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

## التقاط اللافتات (Banner Grabbing)

تحديد الخدمات العاملة على المنافذ المفتوحة عن طريق قراءة لافتاتها.

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
