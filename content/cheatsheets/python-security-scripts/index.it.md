---
title: "Python Black Hat: Scripting di Rete e Sicurezza"
description: "Cheatsheet di scripting Python per la sicurezza informatica: programmazione socket, manipolazione pacchetti con Scapy, richieste HTTP e scansione porte. Frammenti di codice essenziali per penetration tester e ricercatori di sicurezza."
date: 2026-02-10
tags: ["python", "cheatsheet", "penetration-testing", "security", "scripting"]
keywords: ["programmazione socket python", "cheat sheet scapy", "libreria requests python", "script hacking python", "port scanner python", "sicurezza di rete python", "penetration testing python", "creazione pacchetti scapy", "reverse shell python", "automazione sicurezza python"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python Black Hat: Scripting di Rete e Sicurezza",
    "description": "Script Python essenziali per la sicurezza di rete, programmazione socket, manipolazione pacchetti con Scapy e richieste HTTP.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "it"
  }
---

## Inizializzazione del Sistema

Python è la lingua franca della sicurezza offensiva. La sua sintassi leggibile, l'ampia libreria standard e i potenti pacchetti di terze parti lo rendono lo strumento preferito per penetration tester, red teamer e ricercatori di sicurezza che necessitano di automatizzare la ricognizione, creare exploit personalizzati e costruire strumenti di rete. Dalla programmazione socket grezza alla manipolazione dei pacchetti con Scapy fino al testing di applicazioni web con Requests, Python offre il pieno controllo su ogni livello dello stack di rete. Questo manuale operativo contiene frammenti di codice collaudati per le attività di scripting di sicurezza più comuni — pronti per essere copiati, adattati e distribuiti durante incarichi autorizzati.

Tutti gli script sono destinati esclusivamente a test di sicurezza autorizzati e scopi educativi.

---

## Networking con Socket

Il modulo `socket` fornisce l'interfaccia di rete a basso livello in Python. Offre accesso diretto alla comunicazione TCP e UDP, permettendo di costruire client personalizzati, server, scanner di porte e strumenti di rete da zero. Comprendere i socket è fondamentale — ogni libreria di rete di livello superiore è costruita su di essi.

### Client TCP

Stabilire una connessione con un host remoto e scambiare dati.

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

Inviare dati tramite UDP (protocollo senza connessione).

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

### Server TCP

Ascoltare le connessioni in entrata e gestire i client in thread separati.

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

## Manipolazione Pacchetti con Scapy

Scapy è lo strumento definitivo per la creazione di pacchetti, lo sniffing e la scoperta di rete in Python. Permette di costruire pacchetti livello per livello, inviarli sulla rete, catturare le risposte e analizzare il traffico — tutto da uno script Python. Installare con `pip install scapy`.

### Sniffing dei Pacchetti

Catturare il traffico in tempo reale su un'interfaccia di rete.

```python
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Sniff 10 packets on the default interface
sniff(prn=packet_callback, count=10, store=0)
```

### Creazione e Invio di Pacchetti (Ping ICMP)

Costruire una richiesta echo ICMP personalizzata e inviarla.

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

### Scanner ARP (Scoperta di Rete)

Scoprire tutti gli host attivi su una rete locale usando richieste ARP.

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

### Scansione TCP SYN (Scansione Stealth delle Porte)

Creare manualmente pacchetti SYN per rilevare porte aperte senza completare l'handshake.

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

## Richieste HTTP (Contesto di Sicurezza)

La libreria `requests` semplifica la comunicazione HTTP per il testing di applicazioni web, il fuzzing delle API e la ricognizione automatizzata. Installare con `pip install requests`.

### Richieste GET con Header Personalizzati

Aggirare le regole base del WAF o i filtri di fingerprinting falsificando gli header.

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

### Richiesta POST (Brute Force Login)

Test automatizzato delle credenziali contro un modulo di login.

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

### Bruteforce delle Directory

Scoprire percorsi e file nascosti su un server web.

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

## Scanner di Porte Semplice

Uno scanner di porte TCP multi-thread che utilizza socket e threading della libreria standard. Scansiona rapidamente le prime 1024 porte distribuendo il lavoro su più thread.

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

Identificare i servizi in esecuzione sulle porte aperte leggendo i loro banner.

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
