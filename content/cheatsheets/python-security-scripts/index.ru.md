---
title: "Python Black Hat: Сетевые скрипты и скрипты безопасности"
description: "Шпаргалка по скриптам безопасности на Python: программирование сокетов, манипуляция пакетами с Scapy, HTTP-запросы и сканирование портов. Незаменимые фрагменты кода для пентестеров и исследователей безопасности."
date: 2026-02-10
tags: ["python", "cheatsheet", "penetration-testing", "security", "scripting"]
keywords: ["программирование сокетов python", "шпаргалка scapy", "библиотека requests python", "скрипты взлома python", "сканер портов python", "сетевая безопасность python", "тестирование на проникновение python", "создание пакетов scapy", "reverse shell python", "автоматизация безопасности python"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python Black Hat: Сетевые скрипты и скрипты безопасности",
    "description": "Незаменимые скрипты Python для сетевой безопасности, программирования сокетов, манипуляции пакетами с Scapy и HTTP-запросов.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ru"
  }
---

## Инициализация системы

Python — это лингва франка наступательной безопасности. Его читаемый синтаксис, обширная стандартная библиотека и мощные сторонние пакеты делают его инструментом выбора для пентестеров, членов красных команд и исследователей безопасности, которым необходимо автоматизировать разведку, создавать пользовательские эксплойты и строить сетевые инструменты. От низкоуровневого программирования сокетов до манипуляции пакетами с Scapy и тестирования веб-приложений с Requests — Python даёт полный контроль над каждым уровнем сетевого стека. Это полевое руководство содержит проверенные на практике фрагменты кода для наиболее распространённых задач скриптинга безопасности — готовые к копированию, адаптации и развёртыванию при авторизованных мероприятиях.

Все скрипты предназначены исключительно для авторизованного тестирования безопасности и образовательных целей.

---

## Сетевое программирование с сокетами

Модуль `socket` предоставляет низкоуровневый сетевой интерфейс в Python. Он даёт прямой доступ к TCP- и UDP-коммуникации, позволяя создавать пользовательские клиенты, серверы, сканеры портов и сетевые инструменты с нуля. Понимание сокетов является фундаментальным — каждая сетевая библиотека более высокого уровня построена на их основе.

### TCP-клиент

Установить соединение с удалённым хостом и обменяться данными.

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

### UDP-клиент

Отправить данные по UDP (протокол без установления соединения).

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

### TCP-сервер

Прослушивать входящие соединения и обрабатывать клиентов в отдельных потоках.

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

## Манипуляция пакетами с Scapy

Scapy — это абсолютный инструмент для создания пакетов, сниффинга и обнаружения сетей в Python. Он позволяет создавать пакеты послойно, отправлять их по сети, перехватывать ответы и анализировать трафик — всё из Python-скрипта. Установка: `pip install scapy`.

### Сниффинг пакетов

Захват живого трафика на сетевом интерфейсе.

```python
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Sniff 10 packets on the default interface
sniff(prn=packet_callback, count=10, store=0)
```

### Создание и отправка пакетов (ICMP-пинг)

Создать пользовательский ICMP echo-запрос и отправить его.

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

### ARP-сканер (обнаружение сети)

Обнаружить все активные хосты в локальной сети с помощью ARP-запросов.

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

### TCP SYN-сканирование (скрытое сканирование портов)

Вручную создавать SYN-пакеты для обнаружения открытых портов без завершения рукопожатия.

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

## HTTP-запросы (контекст безопасности)

Библиотека `requests` упрощает HTTP-коммуникацию для тестирования веб-приложений, фаззинга API и автоматизированной разведки. Установка: `pip install requests`.

### GET-запросы с пользовательскими заголовками

Обход базовых правил WAF или фильтров по отпечаткам путём подмены заголовков.

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

### POST-запрос (брутфорс авторизации)

Автоматизированная проверка учётных данных на форме входа.

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

### Брутфорс директорий

Обнаружение скрытых путей и файлов на веб-сервере.

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

## Простой сканер портов

Многопоточный TCP-сканер портов с использованием стандартных библиотечных сокетов и потоков. Быстро сканирует первые 1024 порта, распределяя работу между несколькими потоками.

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

## Захват баннеров (Banner Grabbing)

Идентификация сервисов на открытых портах путём чтения их баннеров.

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
