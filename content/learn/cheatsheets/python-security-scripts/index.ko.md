---
title: "Python Black Hat: 네트워크 및 보안 스크립팅"
description: "소켓 프로그래밍, Scapy 패킷 조작, HTTP 요청, 포트 스캐닝을 다루는 Python 보안 스크립팅 치트시트. 침투 테스터와 보안 연구자를 위한 필수 코드 스니펫."
date: 2026-02-10
tags: ["python", "cheatsheet", "penetration-testing", "security", "scripting"]
keywords: ["Python 소켓 프로그래밍", "Scapy 치트시트", "requests 라이브러리 Python", "Python 해킹 스크립트", "Python 포트 스캐너", "Python 네트워크 보안", "Python 침투 테스트", "Scapy 패킷 생성", "Python 리버스 쉘", "Python 보안 자동화"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python Black Hat: 네트워크 및 보안 스크립팅",
    "description": "네트워크 보안, 소켓 프로그래밍, Scapy 패킷 조작, HTTP 요청을 위한 필수 Python 스크립트.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ko"
  }
---

## 시스템 초기화

Python은 공격적 보안의 공용어입니다. 읽기 쉬운 구문, 광범위한 표준 라이브러리, 강력한 서드파티 패키지 덕분에 정찰 자동화, 맞춤형 익스플로잇 제작, 네트워크 도구 구축이 필요한 침투 테스터, 레드 팀원, 보안 연구자에게 최고의 도구가 되었습니다. 로우 소켓 프로그래밍부터 Scapy를 이용한 패킷 조작, Requests를 이용한 웹 애플리케이션 테스트까지, Python은 네트워크 스택의 모든 계층에 대한 완전한 제어를 제공합니다. 이 현장 매뉴얼에는 가장 일반적인 보안 스크립팅 작업을 위한 실전에서 검증된 코드 스니펫이 포함되어 있습니다 — 승인된 업무 중에 복사, 수정, 배포할 준비가 되어 있습니다.

모든 스크립트는 승인된 보안 테스트 및 교육 목적으로만 사용할 수 있습니다.

---

## 소켓 네트워킹

`socket` 모듈은 Python에서 저수준 네트워킹 인터페이스를 제공합니다. TCP 및 UDP 통신에 직접 접근할 수 있어 맞춤형 클라이언트, 서버, 포트 스캐너, 네트워크 도구를 처음부터 만들 수 있습니다. 소켓을 이해하는 것은 필수입니다 — 모든 상위 레벨 네트워킹 라이브러리는 소켓 위에 구축되어 있습니다.

### TCP 클라이언트

원격 호스트에 연결을 설정하고 데이터를 교환합니다.

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

### UDP 클라이언트

UDP(비연결형 프로토콜)로 데이터를 전송합니다.

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

### TCP 서버

수신 연결을 수신 대기하고 별도의 스레드에서 클라이언트를 처리합니다.

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

## Scapy 패킷 조작

Scapy는 Python에서 패킷 생성, 스니핑, 네트워크 발견을 위한 최고의 도구입니다. 레이어별로 패킷을 구성하고, 네트워크로 전송하고, 응답을 캡처하고, 트래픽을 분석할 수 있습니다 — 모두 Python 스크립트에서 가능합니다. `pip install scapy`로 설치하세요.

### 패킷 스니핑

네트워크 인터페이스에서 실시간 트래픽을 캡처합니다.

```python
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Sniff 10 packets on the default interface
sniff(prn=packet_callback, count=10, store=0)
```

### 패킷 생성 및 전송 (ICMP 핑)

맞춤형 ICMP 에코 요청을 생성하고 전송합니다.

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

### ARP 스캐너 (네트워크 발견)

ARP 요청을 사용하여 로컬 네트워크의 모든 활성 호스트를 발견합니다.

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

### TCP SYN 스캔 (스텔스 포트 스캔)

핸드셰이크를 완료하지 않고 열린 포트를 탐지하기 위해 수동으로 SYN 패킷을 생성합니다.

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

## HTTP 요청 (보안 컨텍스트)

`requests` 라이브러리는 웹 애플리케이션 테스트, API 퍼징, 자동화된 정찰을 위한 HTTP 통신을 간소화합니다. `pip install requests`로 설치하세요.

### 커스텀 헤더가 포함된 GET 요청

헤더 스푸핑을 통해 기본 WAF 규칙이나 핑거프린트 필터를 우회합니다.

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

### POST 요청 (로그인 브루트 포스)

로그인 폼에 대한 자동화된 자격 증명 테스트.

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

### 디렉토리 브루트포스

웹 서버에서 숨겨진 경로와 파일을 발견합니다.

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

## 간단한 포트 스캐너

표준 라이브러리의 소켓과 스레딩을 사용한 멀티스레드 TCP 포트 스캐너. 여러 스레드에 작업을 분배하여 처음 1024개 포트를 빠르게 스캔합니다.

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

## 배너 그래빙

열린 포트에서 실행 중인 서비스의 배너를 읽어 식별합니다.

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
