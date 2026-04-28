---
title: "Python Black Hat: Netzwerk- und Sicherheits-Scripting"
description: "Python-Sicherheits-Scripting-Cheatsheet zu Socket-Programmierung, Scapy-Paketmanipulation, HTTP-Anfragen und Port-Scanning. Unverzichtbare Code-Snippets für Penetrationstester und Sicherheitsforscher."
date: 2026-02-10
tags: ["python", "cheatsheet", "penetration-testing", "security", "scripting"]
keywords: ["Python Socket-Programmierung", "Scapy Cheat Sheet", "Requests-Bibliothek Python", "Python Hacking-Skripte", "Python Port-Scanner", "Python Netzwerksicherheit", "Python Penetrationstest", "Scapy Paketerstellung", "Python Reverse Shell", "Python Sicherheitsautomatisierung"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python Black Hat: Netzwerk- und Sicherheits-Scripting",
    "description": "Unverzichtbare Python-Skripte für Netzwerksicherheit, Socket-Programmierung, Scapy-Paketmanipulation und HTTP-Anfragen.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "de"
  }
---

## Systeminitialisierung

Python ist die Lingua Franca der offensiven Sicherheit. Seine lesbare Syntax, die umfangreiche Standardbibliothek und leistungsfähige Drittanbieter-Pakete machen es zum Werkzeug der Wahl für Penetrationstester, Red Teamer und Sicherheitsforscher, die Aufklärung automatisieren, individuelle Exploits erstellen und Netzwerktools entwickeln müssen. Von der Raw-Socket-Programmierung über die Paketmanipulation mit Scapy bis hin zu Webanwendungstests mit Requests gibt Python die volle Kontrolle über jede Schicht des Netzwerk-Stacks. Dieses Feldhandbuch enthält praxiserprobte Code-Snippets für die gängigsten Sicherheits-Scripting-Aufgaben — bereit zum Kopieren, Anpassen und Einsetzen bei autorisierten Einsätzen.

Alle Skripte sind ausschließlich für autorisierte Sicherheitstests und Bildungszwecke bestimmt.

---

## Socket-Netzwerkprogrammierung

Das `socket`-Modul stellt die Low-Level-Netzwerkschnittstelle in Python bereit. Es bietet direkten Zugriff auf TCP- und UDP-Kommunikation und ermöglicht den Aufbau individueller Clients, Server, Port-Scanner und Netzwerktools von Grund auf. Das Verständnis von Sockets ist grundlegend — jede höhere Netzwerkbibliothek baut darauf auf.

### TCP-Client

Eine Verbindung zu einem Remote-Host herstellen und Daten austauschen.

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

### UDP-Client

Daten über UDP senden (verbindungsloses Protokoll).

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

### TCP-Server

Eingehende Verbindungen abhören und Clients in separaten Threads verarbeiten.

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

## Scapy-Paketmanipulation

Scapy ist das ultimative Werkzeug für Paketerstellung, Sniffing und Netzwerkerkennung in Python. Es ermöglicht den Aufbau von Paketen Schicht für Schicht, deren Versand über das Netzwerk, das Erfassen von Antworten und die Analyse des Datenverkehrs — alles aus einem Python-Skript heraus. Installation mit `pip install scapy`.

### Pakete sniffen

Live-Datenverkehr auf einer Netzwerkschnittstelle erfassen.

```python
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Sniff 10 packets on the default interface
sniff(prn=packet_callback, count=10, store=0)
```

### Pakete erstellen und senden (ICMP-Ping)

Eine benutzerdefinierte ICMP-Echo-Anfrage erstellen und senden.

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

### ARP-Scanner (Netzwerkerkennung)

Alle aktiven Hosts in einem lokalen Netzwerk mithilfe von ARP-Anfragen entdecken.

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

### TCP-SYN-Scan (Stealth-Port-Scan)

Manuell SYN-Pakete erstellen, um offene Ports zu erkennen, ohne den Handshake abzuschließen.

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

## HTTP-Anfragen (Sicherheitskontext)

Die `requests`-Bibliothek vereinfacht die HTTP-Kommunikation für Webanwendungstests, API-Fuzzing und automatisierte Aufklärung. Installation mit `pip install requests`.

### GET-Anfragen mit benutzerdefinierten Headern

Einfache WAF-Regeln oder Fingerprint-Filter durch Header-Spoofing umgehen.

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

### POST-Anfrage (Login-Brute-Force)

Automatisiertes Testen von Anmeldeinformationen gegen ein Login-Formular.

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

### Verzeichnis-Brute-Force

Versteckte Pfade und Dateien auf einem Webserver entdecken.

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

## Einfacher Port-Scanner

Ein Multi-Thread-TCP-Port-Scanner unter Verwendung von Standard-Bibliotheks-Sockets und Threading. Scannt die ersten 1024 Ports schnell, indem die Arbeit auf mehrere Threads verteilt wird.

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

Dienste auf offenen Ports durch Auslesen ihrer Banner identifizieren.

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
