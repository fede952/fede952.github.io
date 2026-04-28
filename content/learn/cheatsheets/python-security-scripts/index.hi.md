---
title: "Python Black Hat: नेटवर्क और सुरक्षा स्क्रिप्टिंग"
description: "सॉकेट प्रोग्रामिंग, Scapy पैकेट मैनिपुलेशन, HTTP अनुरोध और पोर्ट स्कैनिंग को कवर करने वाली Python सुरक्षा स्क्रिप्टिंग चीटशीट। पेनिट्रेशन टेस्टर और सुरक्षा शोधकर्ताओं के लिए आवश्यक कोड स्निपेट।"
date: 2026-02-10
tags: ["python", "cheatsheet", "penetration-testing", "security", "scripting"]
keywords: ["Python सॉकेट प्रोग्रामिंग", "Scapy चीट शीट", "requests लाइब्रेरी Python", "Python हैकिंग स्क्रिप्ट", "Python पोर्ट स्कैनर", "Python नेटवर्क सुरक्षा", "Python पेनिट्रेशन टेस्टिंग", "Scapy पैकेट क्राफ्टिंग", "Python रिवर्स शेल", "Python सुरक्षा ऑटोमेशन"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python Black Hat: नेटवर्क और सुरक्षा स्क्रिप्टिंग",
    "description": "नेटवर्क सुरक्षा, सॉकेट प्रोग्रामिंग, Scapy पैकेट मैनिपुलेशन और HTTP अनुरोधों के लिए आवश्यक Python स्क्रिप्ट।",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "hi"
  }
---

## सिस्टम इनिशियलाइज़ेशन

Python आक्रामक सुरक्षा की सार्वभौमिक भाषा है। इसका पठनीय सिंटैक्स, व्यापक स्टैंडर्ड लाइब्रेरी और शक्तिशाली थर्ड-पार्टी पैकेज इसे पेनिट्रेशन टेस्टर, रेड टीमर और सुरक्षा शोधकर्ताओं के लिए पसंदीदा उपकरण बनाते हैं, जिन्हें रिकॉनसेन्स को ऑटोमेट करने, कस्टम एक्सप्लॉइट बनाने और नेटवर्क टूल्स विकसित करने की आवश्यकता होती है। रॉ सॉकेट प्रोग्रामिंग से लेकर Scapy के साथ पैकेट मैनिपुलेशन और Requests के साथ वेब एप्लिकेशन टेस्टिंग तक, Python आपको नेटवर्क स्टैक की हर परत पर पूर्ण नियंत्रण देता है। इस फील्ड मैनुअल में सबसे आम सुरक्षा स्क्रिप्टिंग कार्यों के लिए युद्ध-परीक्षित कोड स्निपेट शामिल हैं — अधिकृत कार्यों के दौरान कॉपी, अनुकूलित और तैनात करने के लिए तैयार।

सभी स्क्रिप्ट केवल अधिकृत सुरक्षा परीक्षण और शैक्षिक उद्देश्यों के लिए हैं।

---

## सॉकेट नेटवर्किंग

`socket` मॉड्यूल Python में निम्न-स्तरीय नेटवर्किंग इंटरफ़ेस प्रदान करता है। यह TCP और UDP संचार तक सीधी पहुंच देता है, जिससे आप कस्टम क्लाइंट, सर्वर, पोर्ट स्कैनर और नेटवर्क टूल्स शुरू से बना सकते हैं। सॉकेट को समझना मूलभूत है — हर उच्च-स्तरीय नेटवर्किंग लाइब्रेरी उन पर बनी है।

### TCP क्लाइंट

एक रिमोट होस्ट से कनेक्शन स्थापित करें और डेटा का आदान-प्रदान करें।

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

### UDP क्लाइंट

UDP (कनेक्शनलेस प्रोटोकॉल) पर डेटा भेजें।

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

### TCP सर्वर

आने वाले कनेक्शनों को सुनें और अलग-अलग थ्रेड्स में क्लाइंट्स को संभालें।

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

## Scapy पैकेट मैनिपुलेशन

Scapy Python में पैकेट क्राफ्टिंग, स्निफिंग और नेटवर्क डिस्कवरी के लिए अंतिम उपकरण है। यह आपको परत दर परत पैकेट बनाने, उन्हें नेटवर्क पर भेजने, प्रतिक्रियाएं कैप्चर करने और ट्रैफ़िक का विश्लेषण करने देता है — सब कुछ एक Python स्क्रिप्ट से। `pip install scapy` से इंस्टॉल करें।

### पैकेट स्निफिंग

नेटवर्क इंटरफ़ेस पर लाइव ट्रैफ़िक कैप्चर करें।

```python
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Sniff 10 packets on the default interface
sniff(prn=packet_callback, count=10, store=0)
```

### पैकेट बनाना और भेजना (ICMP पिंग)

एक कस्टम ICMP इको रिक्वेस्ट बनाएं और भेजें।

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

### ARP स्कैनर (नेटवर्क डिस्कवरी)

ARP अनुरोधों का उपयोग करके स्थानीय नेटवर्क पर सभी सक्रिय होस्ट खोजें।

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

### TCP SYN स्कैन (स्टेल्थ पोर्ट स्कैन)

हैंडशेक पूरा किए बिना खुले पोर्ट का पता लगाने के लिए मैन्युअल रूप से SYN पैकेट बनाएं।

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

## HTTP अनुरोध (सुरक्षा संदर्भ)

`requests` लाइब्रेरी वेब एप्लिकेशन टेस्टिंग, API फ़ज़िंग और स्वचालित रिकॉनसेन्स के लिए HTTP संचार को सरल बनाती है। `pip install requests` से इंस्टॉल करें।

### कस्टम हेडर के साथ GET अनुरोध

हेडर स्पूफिंग द्वारा बुनियादी WAF नियमों या फिंगरप्रिंट फ़िल्टर को बायपास करें।

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

### POST अनुरोध (लॉगिन ब्रूट फोर्स)

लॉगिन फॉर्म के खिलाफ स्वचालित क्रेडेंशियल परीक्षण।

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

### डायरेक्टरी ब्रूटफोर्स

वेब सर्वर पर छिपे हुए पथ और फ़ाइलें खोजें।

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

## सरल पोर्ट स्कैनर

स्टैंडर्ड लाइब्रेरी सॉकेट और थ्रेडिंग का उपयोग करने वाला एक मल्टी-थ्रेडेड TCP पोर्ट स्कैनर। कई थ्रेड्स में काम वितरित करके पहले 1024 पोर्ट को तेज़ी से स्कैन करता है।

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

## बैनर ग्रैबिंग

खुले पोर्ट पर चल रही सेवाओं के बैनर पढ़कर उनकी पहचान करें।

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
