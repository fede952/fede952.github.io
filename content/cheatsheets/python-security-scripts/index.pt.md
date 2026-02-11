---
title: "Python Black Hat: Scripting de Rede e Segurança"
description: "Cheatsheet de scripting Python para segurança cobrindo programação de sockets, manipulação de pacotes com Scapy, requisições HTTP e varredura de portas. Trechos de código essenciais para pentesters e pesquisadores de segurança."
date: 2026-02-10
tags: ["python", "cheatsheet", "penetration-testing", "security", "scripting"]
keywords: ["programação socket python", "cheat sheet scapy", "biblioteca requests python", "scripts hacking python", "scanner de portas python", "segurança de rede python", "teste de penetração python", "criação de pacotes scapy", "reverse shell python", "automação de segurança python"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python Black Hat: Scripting de Rede e Segurança",
    "description": "Scripts Python essenciais para segurança de rede, programação de sockets, manipulação de pacotes com Scapy e requisições HTTP.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "pt"
  }
---

## Inicialização do Sistema

Python é a língua franca da segurança ofensiva. Sua sintaxe legível, extensa biblioteca padrão e poderosos pacotes de terceiros o tornam a ferramenta preferida para pentesters, red teamers e pesquisadores de segurança que precisam automatizar reconhecimento, criar exploits personalizados e construir ferramentas de rede. Da programação de sockets brutos à manipulação de pacotes com Scapy e testes de aplicações web com Requests, Python oferece controle total sobre cada camada da pilha de rede. Este manual de campo contém trechos de código testados em batalha para as tarefas de scripting de segurança mais comuns — prontos para copiar, adaptar e implantar durante engajamentos autorizados.

Todos os scripts são destinados exclusivamente a testes de segurança autorizados e fins educacionais.

---

## Rede com Sockets

O módulo `socket` fornece a interface de rede de baixo nível em Python. Ele dá acesso direto à comunicação TCP e UDP, permitindo construir clientes personalizados, servidores, scanners de portas e ferramentas de rede do zero. Compreender sockets é fundamental — toda biblioteca de rede de nível superior é construída sobre eles.

### Cliente TCP

Estabelecer uma conexão com um host remoto e trocar dados.

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

### Cliente UDP

Enviar dados via UDP (protocolo sem conexão).

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

### Servidor TCP

Escutar conexões de entrada e tratar clientes em threads separadas.

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

## Manipulação de Pacotes com Scapy

Scapy é a ferramenta definitiva para criação de pacotes, sniffing e descoberta de rede em Python. Permite construir pacotes camada por camada, enviá-los pela rede, capturar respostas e dissecar o tráfego — tudo a partir de um script Python. Instalar com `pip install scapy`.

### Sniffing de Pacotes

Capturar tráfego ao vivo em uma interface de rede.

```python
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Sniff 10 packets on the default interface
sniff(prn=packet_callback, count=10, store=0)
```

### Criação e Envio de Pacotes (Ping ICMP)

Construir uma requisição echo ICMP personalizada e enviá-la.

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

### Scanner ARP (Descoberta de Rede)

Descobrir todos os hosts ativos em uma rede local usando requisições ARP.

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

### Varredura TCP SYN (Varredura Stealth de Portas)

Criar manualmente pacotes SYN para detectar portas abertas sem completar o handshake.

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

## Requisições HTTP (Contexto de Segurança)

A biblioteca `requests` simplifica a comunicação HTTP para testes de aplicações web, fuzzing de APIs e reconhecimento automatizado. Instalar com `pip install requests`.

### Requisições GET com Headers Personalizados

Contornar regras básicas de WAF ou filtros de fingerprinting falsificando headers.

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

### Requisição POST (Força Bruta de Login)

Teste automatizado de credenciais contra um formulário de login.

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

### Força Bruta de Diretórios

Descobrir caminhos e arquivos ocultos em um servidor web.

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

## Scanner de Portas Simples

Um scanner de portas TCP multi-thread usando sockets e threading da biblioteca padrão. Varre rapidamente as primeiras 1024 portas distribuindo o trabalho entre múltiplas threads.

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

## Banner Grabbing

Identificar os serviços em execução nas portas abertas lendo seus banners.

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
