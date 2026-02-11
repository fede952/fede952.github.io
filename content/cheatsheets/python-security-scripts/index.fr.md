---
title: "Python Black Hat : Scripting Réseau et Sécurité"
description: "Cheatsheet de scripting Python pour la sécurité couvrant la programmation socket, la manipulation de paquets avec Scapy, les requêtes HTTP et le scan de ports. Extraits de code essentiels pour les testeurs d'intrusion et les chercheurs en sécurité."
date: 2026-02-10
tags: ["python", "cheatsheet", "penetration-testing", "security", "scripting"]
keywords: ["programmation socket python", "cheat sheet scapy", "bibliothèque requests python", "scripts hacking python", "scanner de ports python", "sécurité réseau python", "test d'intrusion python", "création de paquets scapy", "reverse shell python", "automatisation sécurité python"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python Black Hat : Scripting Réseau et Sécurité",
    "description": "Scripts Python essentiels pour la sécurité réseau, la programmation socket, la manipulation de paquets avec Scapy et les requêtes HTTP.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "fr"
  }
---

## Initialisation du Système

Python est la lingua franca de la sécurité offensive. Sa syntaxe lisible, sa vaste bibliothèque standard et ses puissants paquets tiers en font l'outil de prédilection des testeurs d'intrusion, des red teamers et des chercheurs en sécurité qui ont besoin d'automatiser la reconnaissance, de créer des exploits personnalisés et de construire des outils réseau. De la programmation socket brute à la manipulation de paquets avec Scapy en passant par les tests d'applications web avec Requests, Python vous donne un contrôle total sur chaque couche de la pile réseau. Ce manuel de terrain contient des extraits de code éprouvés pour les tâches de scripting de sécurité les plus courantes — prêts à être copiés, adaptés et déployés lors de missions autorisées.

Tous les scripts sont destinés uniquement aux tests de sécurité autorisés et à des fins éducatives.

---

## Réseau avec les Sockets

Le module `socket` fournit l'interface réseau de bas niveau en Python. Il donne un accès direct à la communication TCP et UDP, permettant de construire des clients personnalisés, des serveurs, des scanners de ports et des outils réseau à partir de zéro. Comprendre les sockets est fondamental — chaque bibliothèque réseau de niveau supérieur est construite dessus.

### Client TCP

Établir une connexion avec un hôte distant et échanger des données.

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

### Client UDP

Envoyer des données via UDP (protocole sans connexion).

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

### Serveur TCP

Écouter les connexions entrantes et gérer les clients dans des threads séparés.

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

## Manipulation de Paquets avec Scapy

Scapy est l'outil ultime pour la création de paquets, le sniffing et la découverte réseau en Python. Il permet de construire des paquets couche par couche, de les envoyer sur le réseau, de capturer les réponses et de disséquer le trafic — le tout depuis un script Python. Installer avec `pip install scapy`.

### Sniffing de Paquets

Capturer le trafic en direct sur une interface réseau.

```python
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Sniff 10 packets on the default interface
sniff(prn=packet_callback, count=10, store=0)
```

### Création et Envoi de Paquets (Ping ICMP)

Construire une requête echo ICMP personnalisée et l'envoyer.

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

### Scanner ARP (Découverte Réseau)

Découvrir tous les hôtes actifs sur un réseau local à l'aide de requêtes ARP.

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

### Scan TCP SYN (Scan Furtif de Ports)

Créer manuellement des paquets SYN pour détecter les ports ouverts sans compléter le handshake.

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

## Requêtes HTTP (Contexte de Sécurité)

La bibliothèque `requests` simplifie la communication HTTP pour les tests d'applications web, le fuzzing d'API et la reconnaissance automatisée. Installer avec `pip install requests`.

### Requêtes GET avec En-têtes Personnalisés

Contourner les règles basiques du WAF ou les filtres de fingerprinting en falsifiant les en-têtes.

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

### Requête POST (Force Brute de Login)

Test automatisé des identifiants contre un formulaire de connexion.

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

### Force Brute de Répertoires

Découvrir les chemins et fichiers cachés sur un serveur web.

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

## Scanner de Ports Simple

Un scanner de ports TCP multi-thread utilisant les sockets et le threading de la bibliothèque standard. Scanne rapidement les 1024 premiers ports en répartissant le travail sur plusieurs threads.

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

Identifier les services exécutés sur les ports ouverts en lisant leurs bannières.

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
