---
title: "Python Black Hat: Scripting de Redes y Seguridad"
description: "Cheatsheet de scripting Python para seguridad que cubre programación de sockets, manipulación de paquetes con Scapy, solicitudes HTTP y escaneo de puertos. Fragmentos de código esenciales para pentesters e investigadores de seguridad."
date: 2026-02-10
tags: ["python", "cheatsheet", "penetration-testing", "security", "scripting"]
keywords: ["programación socket python", "cheat sheet scapy", "librería requests python", "scripts hacking python", "escáner de puertos python", "seguridad de red python", "pruebas de penetración python", "creación de paquetes scapy", "reverse shell python", "automatización de seguridad python"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python Black Hat: Scripting de Redes y Seguridad",
    "description": "Scripts esenciales de Python para seguridad de redes, programación de sockets, manipulación de paquetes con Scapy y solicitudes HTTP.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "es"
  }
---

## Inicio del Sistema

Python es la lingua franca de la seguridad ofensiva. Su sintaxis legible, su extensa biblioteca estándar y sus potentes paquetes de terceros lo convierten en la herramienta preferida para pentesters, red teamers e investigadores de seguridad que necesitan automatizar el reconocimiento, crear exploits personalizados y construir herramientas de red. Desde la programación de sockets en crudo hasta la manipulación de paquetes con Scapy y las pruebas de aplicaciones web con Requests, Python te da control total sobre cada capa de la pila de red. Este manual de campo contiene fragmentos de código probados en batalla para las tareas de scripting de seguridad más comunes — listos para copiar, adaptar y desplegar durante compromisos autorizados.

Todos los scripts son únicamente para pruebas de seguridad autorizadas y fines educativos.

---

## Networking con Sockets

El módulo `socket` proporciona la interfaz de red de bajo nivel en Python. Te da acceso directo a la comunicación TCP y UDP, permitiéndote construir clientes personalizados, servidores, escáneres de puertos y herramientas de red desde cero. Comprender los sockets es fundamental — toda biblioteca de red de nivel superior está construida sobre ellos.

### Cliente TCP

Establecer una conexión con un host remoto e intercambiar datos.

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

Enviar datos a través de UDP (protocolo sin conexión).

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

Escuchar conexiones entrantes y manejar clientes en hilos separados.

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

## Manipulación de Paquetes con Scapy

Scapy es la herramienta definitiva para la creación de paquetes, sniffing y descubrimiento de redes en Python. Te permite construir paquetes capa por capa, enviarlos por la red, capturar respuestas y diseccionar el tráfico — todo desde un script de Python. Instalar con `pip install scapy`.

### Sniffing de Paquetes

Capturar tráfico en vivo en una interfaz de red.

```python
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Sniff 10 packets on the default interface
sniff(prn=packet_callback, count=10, store=0)
```

### Creación y Envío de Paquetes (Ping ICMP)

Construir una solicitud echo ICMP personalizada y enviarla.

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

### Escáner ARP (Descubrimiento de Red)

Descubrir todos los hosts activos en una red local usando solicitudes ARP.

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

### Escaneo TCP SYN (Escaneo Sigiloso de Puertos)

Crear manualmente paquetes SYN para detectar puertos abiertos sin completar el handshake.

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

## Solicitudes HTTP (Contexto de Seguridad)

La biblioteca `requests` simplifica la comunicación HTTP para pruebas de aplicaciones web, fuzzing de APIs y reconocimiento automatizado. Instalar con `pip install requests`.

### Solicitudes GET con Headers Personalizados

Eludir reglas básicas de WAF o filtros de fingerprinting falsificando headers.

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

### Solicitud POST (Fuerza Bruta de Login)

Prueba automatizada de credenciales contra un formulario de inicio de sesión.

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

### Fuerza Bruta de Directorios

Descubrir rutas y archivos ocultos en un servidor web.

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

## Escáner de Puertos Simple

Un escáner de puertos TCP multi-hilo que utiliza sockets y threading de la biblioteca estándar. Escanea rápidamente los primeros 1024 puertos distribuyendo el trabajo entre múltiples hilos.

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

Identificar los servicios que se ejecutan en puertos abiertos leyendo sus banners.

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
