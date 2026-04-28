---
title: "خريطة الإنترنت: منافذ الشبكة والبروتوكولات وأكواد الحالة"
description: "دليل مرئي لـ TCP/IP ونموذج OSI والمنافذ الشائعة (SSH، HTTP، DNS) وأكواد حالة HTTP لمهندسي DevOps والهاكرز."
date: 2026-02-13
tags: ["networking", "cheatsheet", "devops", "security", "sysadmin"]
keywords: ["common ports cheat sheet", "http status codes", "tcp vs udp", "osi model explained", "dns records types", "ssh port forwarding"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "خريطة الإنترنت: منافذ الشبكة والبروتوكولات وأكواد الحالة",
    "description": "دليل مرئي لـ TCP/IP ونموذج OSI والمنافذ الشائعة (SSH، HTTP، DNS) وأكواد حالة HTTP لمهندسي DevOps والهاكرز.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ar"
  }
---

## المنافذ الشائعة

كل خدمة على الشبكة تستمع على منفذ. هذه هي المنافذ التي تحتاج لحفظها عن ظهر قلب.

### المنافذ المعروفة (0–1023)

| المنفذ | البروتوكول | الخدمة | ملاحظات |
|--------|-----------|--------|---------|
| 20 | TCP | FTP Data | نقل البيانات في الوضع النشط |
| 21 | TCP | FTP Control | الأوامر والمصادقة |
| 22 | TCP | SSH / SFTP | الصدفة الآمنة ونقل الملفات |
| 23 | TCP | Telnet | وصول عن بعد غير مشفر (تجنّبه) |
| 25 | TCP | SMTP | إرسال البريد الإلكتروني |
| 53 | TCP/UDP | DNS | تحليل أسماء النطاقات |
| 67/68 | UDP | DHCP | تعيين IP ديناميكي |
| 80 | TCP | HTTP | حركة ويب غير مشفرة |
| 110 | TCP | POP3 | استرجاع البريد الإلكتروني |
| 143 | TCP | IMAP | استرجاع البريد (من جانب الخادم) |
| 443 | TCP | HTTPS | حركة ويب مشفرة (TLS) |
| 445 | TCP | SMB | مشاركة ملفات Windows |
| 587 | TCP | SMTP (TLS) | إرسال بريد آمن |

### المنافذ المسجّلة (1024–49151)

| المنفذ | البروتوكول | الخدمة | ملاحظات |
|--------|-----------|--------|---------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | مستمع قاعدة بيانات Oracle |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 3389 | TCP | RDP | بروتوكول سطح المكتب البعيد |
| 5432 | TCP | PostgreSQL | قاعدة بيانات PostgreSQL |
| 5900 | TCP | VNC | الحوسبة الشبكية الافتراضية |
| 6379 | TCP | Redis | مخزن بيانات في الذاكرة |
| 8080 | TCP | HTTP Alt | منفذ تطوير/وكيل شائع |
| 8443 | TCP | HTTPS Alt | منفذ HTTPS بديل |
| 27017 | TCP | MongoDB | قاعدة بيانات MongoDB |

---

## أكواد حالة HTTP

طريقة الخادم لإخبارك بما حدث. مُجمّعة حسب الفئة.

### 1xx — معلوماتية

| الكود | الاسم | المعنى |
|-------|-------|--------|
| 100 | Continue | استمر في إرسال جسم الطلب |
| 101 | Switching Protocols | الترقية إلى WebSocket |

### 2xx — نجاح

| الكود | الاسم | المعنى |
|-------|-------|--------|
| 200 | OK | نجح الطلب |
| 201 | Created | تم إنشاء المورد (نجاح POST) |
| 204 | No Content | نجاح، لكن لا شيء لإرجاعه |

### 3xx — إعادة توجيه

| الكود | الاسم | المعنى |
|-------|-------|--------|
| 301 | Moved Permanently | تغيّر الرابط نهائياً (حدّث الإشارات المرجعية) |
| 302 | Found | إعادة توجيه مؤقتة |
| 304 | Not Modified | استخدم النسخة المخزّنة مؤقتاً |
| 307 | Temporary Redirect | مثل 302، لكن مع الاحتفاظ بطريقة HTTP |
| 308 | Permanent Redirect | مثل 301، لكن مع الاحتفاظ بطريقة HTTP |

### 4xx — أخطاء العميل

| الكود | الاسم | المعنى |
|-------|-------|--------|
| 400 | Bad Request | صياغة خاطئة أو بيانات غير صالحة |
| 401 | Unauthorized | المصادقة مطلوبة |
| 403 | Forbidden | مُصادق عليه لكن غير مُخوّل |
| 404 | Not Found | المورد غير موجود |
| 405 | Method Not Allowed | فعل HTTP خاطئ (GET مقابل POST) |
| 408 | Request Timeout | الخادم ملّ من الانتظار |
| 409 | Conflict | تعارض في الحالة (مثل: تكرار) |
| 413 | Payload Too Large | جسم الطلب يتجاوز الحد |
| 418 | I'm a Teapot | RFC 2324. نعم، إنه حقيقي. |
| 429 | Too Many Requests | تم تحديد المعدل |

### 5xx — أخطاء الخادم

| الكود | الاسم | المعنى |
|-------|-------|--------|
| 500 | Internal Server Error | فشل عام في الخادم |
| 502 | Bad Gateway | الخادم الأعلى أرسل استجابة غير صالحة |
| 503 | Service Unavailable | الخادم محمّل فوق طاقته أو في صيانة |
| 504 | Gateway Timeout | الخادم الأعلى لم يستجب في الوقت المحدد |

---

## TCP مقابل UDP

بروتوكولا طبقة النقل. أدوات مختلفة لمهام مختلفة.

| الميزة | TCP | UDP |
|--------|-----|-----|
| الاتصال | موجّه بالاتصال (مصافحة) | بدون اتصال (أطلق وانسَ) |
| الموثوقية | تسليم مضمون ومُرتّب | بدون ضمان ولا ترتيب |
| السرعة | أبطأ (حمل إضافي) | أسرع (حمل إضافي أقل) |
| حجم الترويسة | 20–60 بايت | 8 بايت |
| التحكم بالتدفق | نعم (نوافذ) | لا |
| حالات الاستخدام | الويب، البريد، نقل الملفات، SSH | DNS، البث، الألعاب، VoIP |

### مصافحة TCP الثلاثية

```
Client              Server
  |--- SYN ----------->|   1. Client sends SYN (seq=x)
  |<-- SYN-ACK --------|   2. Server replies SYN-ACK (seq=y, ack=x+1)
  |--- ACK ----------->|   3. Client sends ACK (ack=y+1)
  |                     |   Connection established
```

### إنهاء اتصال TCP

```
Client              Server
  |--- FIN ----------->|   1. Client initiates close
  |<-- ACK ------------|   2. Server acknowledges
  |<-- FIN ------------|   3. Server ready to close
  |--- ACK ----------->|   4. Client confirms
  |                     |   Connection closed
```

---

## مصافحة SSL/TLS

كيف يُنشئ HTTPS اتصالاً مشفراً.

```
Client                          Server
  |--- ClientHello ------------->|   Supported ciphers, TLS version, random
  |<-- ServerHello --------------|   Chosen cipher, certificate, random
  |    (verify certificate)      |
  |--- Key Exchange ------------>|   Pre-master secret (encrypted with server's public key)
  |    (both derive session key) |
  |--- Finished (encrypted) --->|   First encrypted message
  |<-- Finished (encrypted) ----|   Server confirms
  |                              |   Encrypted communication begins
```

المفاهيم الأساسية:
- **التشفير غير المتماثل** (RSA/ECDSA) يُستخدم فقط للمصافحة
- **التشفير المتماثل** (AES) يُستخدم لنقل البيانات الفعلي (أسرع)
- **TLS 1.3** قلّص المصافحة إلى رحلة ذهاب وإياب واحدة (مقابل 2 في TLS 1.2)

---

## نموذج OSI

سبع طبقات، من الكابلات الفيزيائية إلى متصفحك. كل طبقة تتواصل مع نظيرتها على الطرف الآخر.

| الطبقة | الاسم | أمثلة البروتوكولات | وحدة البيانات | الأجهزة |
|--------|-------|-------------------|--------------|---------|
| 7 | التطبيق | HTTP, FTP, DNS, SMTP | بيانات | — |
| 6 | العرض | SSL/TLS, JPEG, ASCII | بيانات | — |
| 5 | الجلسة | NetBIOS, RPC | بيانات | — |
| 4 | النقل | TCP, UDP | مقطع/مخطط بيانات | — |
| 3 | الشبكة | IP, ICMP, ARP | حزمة | موجّه |
| 2 | ربط البيانات | Ethernet, Wi-Fi, PPP | إطار | مبدّل |
| 1 | الفيزيائية | كابلات، راديو، ألياف | بتات | مُكرّر |

> **للحفظ (من أعلى لأسفل):** **A**ll **P**eople **S**eem **T**o **N**eed **D**ata **P**rocessing

### نموذج TCP/IP (المبسّط)

| طبقة TCP/IP | المقابل في OSI | أمثلة |
|-------------|----------------|-------|
| التطبيق | 7، 6، 5 | HTTP, DNS, SSH |
| النقل | 4 | TCP, UDP |
| الإنترنت | 3 | IP, ICMP |
| الوصول للشبكة | 2، 1 | Ethernet, Wi-Fi |

---

## أنواع سجلات DNS

كيف تُربط أسماء النطاقات بالخدمات.

| النوع | الغرض | مثال |
|-------|-------|------|
| A | نطاق → IPv4 | `example.com → 93.184.216.34` |
| AAAA | نطاق → IPv6 | `example.com → 2606:2800:...` |
| CNAME | اسم مستعار لنطاق آخر | `www.example.com → example.com` |
| MX | خادم البريد | `example.com → mail.example.com` |
| TXT | التحقق، SPF، DKIM | `v=spf1 include:_spf.google.com` |
| NS | تفويض خادم الأسماء | `example.com → ns1.provider.com` |
| SOA | معلومات سلطة المنطقة | التسلسل، التحديث، إعادة المحاولة، الانتهاء |
| SRV | موقع الخدمة | `_sip._tcp.example.com` |
| PTR | بحث عكسي (IP → نطاق) | `34.216.184.93 → example.com` |

---

## إعادة توجيه منافذ SSH

توجيه حركة المرور عبر SSH. ضروري للوصول إلى الخدمات خلف جدران الحماية.

```bash
# Local forwarding: access remote_host:3306 via localhost:9906
ssh -L 9906:localhost:3306 user@remote_host

# Remote forwarding: expose your localhost:3000 on remote:8080
ssh -R 8080:localhost:3000 user@remote_host

# Dynamic forwarding (SOCKS proxy on localhost:1080)
ssh -D 1080 user@remote_host

# Tunnel through a jump host
ssh -J jump_host user@final_host
```

---

## جدول مرجعي سريع

| الوظيفة | الأمر / القيمة |
|---------|----------------|
| فحص المنافذ المفتوحة | `ss -tlnp` أو `netstat -tlnp` |
| مسح المنافذ | `nmap -sV target` |
| استعلام DNS | `dig example.com A` أو `nslookup example.com` |
| تتبع المسار | `traceroute example.com` |
| اختبار الاتصال | `ping -c 4 example.com` |
| طلب HTTP | `curl -I https://example.com` |
| فحص شهادة TLS | `openssl s_client -connect example.com:443` |
| التقاط الحزم | `tcpdump -i eth0 port 80` |
