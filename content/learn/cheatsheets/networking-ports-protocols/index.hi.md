---
title: "इंटरनेट का नक्शा: नेटवर्किंग पोर्ट्स, प्रोटोकॉल और स्टेटस कोड"
description: "TCP/IP, OSI मॉडल, कॉमन पोर्ट्स (SSH, HTTP, DNS), और HTTP स्टेटस कोड की विजुअल गाइड DevOps और हैकर्स के लिए।"
date: 2026-02-13
tags: ["networking", "cheatsheet", "devops", "security", "sysadmin"]
keywords: ["common ports cheat sheet", "http status codes", "tcp vs udp", "osi model explained", "dns records types", "ssh port forwarding"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "इंटरनेट का नक्शा: नेटवर्किंग पोर्ट्स, प्रोटोकॉल और स्टेटस कोड",
    "description": "TCP/IP, OSI मॉडल, कॉमन पोर्ट्स (SSH, HTTP, DNS), और HTTP स्टेटस कोड की विजुअल गाइड DevOps और हैकर्स के लिए।",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "hi"
  }
---

## कॉमन पोर्ट्स

नेटवर्क पर हर सर्विस एक पोर्ट पर सुनती है। ये वो हैं जो आपको जुबानी याद होने चाहिए।

### वेल-नोन पोर्ट्स (0–1023)

| पोर्ट | प्रोटोकॉल | सर्विस | नोट्स |
|------|----------|---------|-------|
| 20 | TCP | FTP Data | एक्टिव मोड डेटा ट्रांसफर |
| 21 | TCP | FTP Control | कमांड और ऑथेंटिकेशन |
| 22 | TCP | SSH / SFTP | सिक्योर शेल और फ़ाइल ट्रांसफर |
| 23 | TCP | Telnet | अनएन्क्रिप्टेड रिमोट एक्सेस (बचें) |
| 25 | TCP | SMTP | ईमेल भेजना |
| 53 | TCP/UDP | DNS | डोमेन नेम रिज़ॉल्यूशन |
| 67/68 | UDP | DHCP | डायनामिक IP असाइनमेंट |
| 80 | TCP | HTTP | अनएन्क्रिप्टेड वेब ट्रैफिक |
| 110 | TCP | POP3 | ईमेल रिट्रीवल |
| 143 | TCP | IMAP | ईमेल रिट्रीवल (सर्वर-साइड) |
| 443 | TCP | HTTPS | एन्क्रिप्टेड वेब ट्रैफिक (TLS) |
| 445 | TCP | SMB | Windows फ़ाइल शेयरिंग |
| 587 | TCP | SMTP (TLS) | सिक्योर ईमेल सबमिशन |

### रजिस्टर्ड पोर्ट्स (1024–49151)

| पोर्ट | प्रोटोकॉल | सर्विस | नोट्स |
|------|----------|---------|-------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Oracle डेटाबेस लिसनर |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 3389 | TCP | RDP | Remote Desktop Protocol |
| 5432 | TCP | PostgreSQL | PostgreSQL डेटाबेस |
| 5900 | TCP | VNC | Virtual Network Computing |
| 6379 | TCP | Redis | इन-मेमोरी डेटा स्टोर |
| 8080 | TCP | HTTP Alt | कॉमन डेव/प्रॉक्सी पोर्ट |
| 8443 | TCP | HTTPS Alt | वैकल्पिक HTTPS पोर्ट |
| 27017 | TCP | MongoDB | MongoDB डेटाबेस |

---

## HTTP स्टेटस कोड

सर्वर आपको बताता है कि क्या हुआ। श्रेणी के अनुसार वर्गीकृत।

### 1xx — सूचनात्मक

| कोड | नाम | अर्थ |
|------|------|---------|
| 100 | Continue | रिक्वेस्ट बॉडी भेजना जारी रखें |
| 101 | Switching Protocols | WebSocket में अपग्रेड हो रहा है |

### 2xx — सफलता

| कोड | नाम | अर्थ |
|------|------|---------|
| 200 | OK | रिक्वेस्ट सफल |
| 201 | Created | रिसोर्स बन गया (POST सफल) |
| 204 | No Content | सफल, लेकिन लौटाने को कुछ नहीं |

### 3xx — रीडायरेक्शन

| कोड | नाम | अर्थ |
|------|------|---------|
| 301 | Moved Permanently | URL हमेशा के लिए बदल गया (बुकमार्क अपडेट करें) |
| 302 | Found | अस्थायी रीडायरेक्ट |
| 304 | Not Modified | कैश्ड वर्शन इस्तेमाल करें |
| 307 | Temporary Redirect | 302 जैसा, लेकिन HTTP मेथड बनाए रखें |
| 308 | Permanent Redirect | 301 जैसा, लेकिन HTTP मेथड बनाए रखें |

### 4xx — क्लाइंट एरर

| कोड | नाम | अर्थ |
|------|------|---------|
| 400 | Bad Request | गलत सिंटैक्स या अमान्य डेटा |
| 401 | Unauthorized | ऑथेंटिकेशन जरूरी है |
| 403 | Forbidden | ऑथेंटिकेटेड लेकिन अधिकृत नहीं |
| 404 | Not Found | रिसोर्स मौजूद नहीं |
| 405 | Method Not Allowed | गलत HTTP वर्ब (GET vs POST) |
| 408 | Request Timeout | सर्वर इंतज़ार करते थक गया |
| 409 | Conflict | स्टेट कॉन्फ्लिक्ट (जैसे, डुप्लीकेट) |
| 413 | Payload Too Large | रिक्वेस्ट बॉडी सीमा से अधिक |
| 418 | I'm a Teapot | RFC 2324। हाँ, यह असली है। |
| 429 | Too Many Requests | रेट लिमिटेड |

### 5xx — सर्वर एरर

| कोड | नाम | अर्थ |
|------|------|---------|
| 500 | Internal Server Error | सामान्य सर्वर विफलता |
| 502 | Bad Gateway | अपस्ट्रीम सर्वर ने अमान्य रिस्पॉन्स भेजा |
| 503 | Service Unavailable | सर्वर ओवरलोड या मेंटेनेंस में |
| 504 | Gateway Timeout | अपस्ट्रीम सर्वर ने समय पर जवाब नहीं दिया |

---

## TCP vs UDP

दो ट्रांसपोर्ट लेयर प्रोटोकॉल। अलग-अलग कामों के लिए अलग-अलग टूल।

| विशेषता | TCP | UDP |
|---------|-----|-----|
| कनेक्शन | कनेक्शन-ओरिएंटेड (हैंडशेक) | कनेक्शनलेस (फायर एंड फॉरगेट) |
| विश्वसनीयता | गारंटीड डिलीवरी, क्रमबद्ध | कोई गारंटी नहीं, कोई क्रम नहीं |
| गति | धीमा (ओवरहेड) | तेज़ (न्यूनतम ओवरहेड) |
| हेडर साइज | 20–60 बाइट्स | 8 बाइट्स |
| फ्लो कंट्रोल | हाँ (विंडोइंग) | नहीं |
| उपयोग | वेब, ईमेल, फ़ाइल ट्रांसफर, SSH | DNS, स्ट्रीमिंग, गेमिंग, VoIP |

### TCP तीन-तरफ़ा हैंडशेक

```
Client              Server
  |--- SYN ----------->|   1. Client SYN भेजता है (seq=x)
  |<-- SYN-ACK --------|   2. Server SYN-ACK जवाब देता है (seq=y, ack=x+1)
  |--- ACK ----------->|   3. Client ACK भेजता है (ack=y+1)
  |                     |   कनेक्शन स्थापित
```

### TCP कनेक्शन समाप्ति

```
Client              Server
  |--- FIN ----------->|   1. Client बंद करने की शुरुआत करता है
  |<-- ACK ------------|   2. Server पुष्टि करता है
  |<-- FIN ------------|   3. Server बंद करने को तैयार
  |--- ACK ----------->|   4. Client पुष्टि करता है
  |                     |   कनेक्शन बंद
```

---

## SSL/TLS हैंडशेक

HTTPS कैसे एन्क्रिप्टेड कनेक्शन स्थापित करता है।

```
Client                          Server
  |--- ClientHello ------------->|   समर्थित सिफर, TLS वर्शन, रैंडम
  |<-- ServerHello --------------|   चुना गया सिफर, सर्टिफिकेट, रैंडम
  |    (सर्टिफिकेट सत्यापन)      |
  |--- Key Exchange ------------>|   प्री-मास्टर सीक्रेट (सर्वर की पब्लिक की से एन्क्रिप्टेड)
  |    (दोनों सेशन की बनाते हैं) |
  |--- Finished (encrypted) --->|   पहला एन्क्रिप्टेड मैसेज
  |<-- Finished (encrypted) ----|   सर्वर पुष्टि करता है
  |                              |   एन्क्रिप्टेड कम्युनिकेशन शुरू
```

मुख्य अवधारणाएं:
- **असिमेट्रिक एन्क्रिप्शन** (RSA/ECDSA) केवल हैंडशेक के लिए इस्तेमाल होता है
- **सिमेट्रिक एन्क्रिप्शन** (AES) वास्तविक डेटा ट्रांसफर के लिए इस्तेमाल होता है (तेज़)
- **TLS 1.3** ने हैंडशेक को 1 राउंड-ट्रिप तक कम कर दिया (TLS 1.2 में 2 की तुलना में)

---

## OSI मॉडल

सात परतें, फिजिकल केबल से लेकर आपके ब्राउज़र तक। हर परत दूसरे सिरे पर अपनी समकक्ष से बात करती है।

| परत | नाम | प्रोटोकॉल उदाहरण | डेटा इकाई | डिवाइस |
|-------|------|-------------------|-----------|---------|
| 7 | Application | HTTP, FTP, DNS, SMTP | Data | — |
| 6 | Presentation | SSL/TLS, JPEG, ASCII | Data | — |
| 5 | Session | NetBIOS, RPC | Data | — |
| 4 | Transport | TCP, UDP | Segment/Datagram | — |
| 3 | Network | IP, ICMP, ARP | Packet | Router |
| 2 | Data Link | Ethernet, Wi-Fi, PPP | Frame | Switch |
| 1 | Physical | Cables, Radio, Fiber | Bits | Hub |

> **याद रखने का तरीका (ऊपर से नीचे):** **A**ll **P**eople **S**eem **T**o **N**eed **D**ata **P**rocessing

### TCP/IP मॉडल (सरलीकृत)

| TCP/IP परत | OSI समतुल्य | उदाहरण |
|--------------|----------------|----------|
| Application | 7, 6, 5 | HTTP, DNS, SSH |
| Transport | 4 | TCP, UDP |
| Internet | 3 | IP, ICMP |
| Network Access | 2, 1 | Ethernet, Wi-Fi |

---

## DNS रिकॉर्ड प्रकार

डोमेन नेम सर्विसेज़ से कैसे जुड़ते हैं।

| प्रकार | उद्देश्य | उदाहरण |
|------|---------|---------|
| A | Domain → IPv4 | `example.com → 93.184.216.34` |
| AAAA | Domain → IPv6 | `example.com → 2606:2800:...` |
| CNAME | दूसरे डोमेन का उपनाम | `www.example.com → example.com` |
| MX | मेल सर्वर | `example.com → mail.example.com` |
| TXT | वेरिफिकेशन, SPF, DKIM | `v=spf1 include:_spf.google.com` |
| NS | नेमसर्वर डेलिगेशन | `example.com → ns1.provider.com` |
| SOA | ज़ोन अथॉरिटी जानकारी | Serial, refresh, retry, expire |
| SRV | सर्विस लोकेशन | `_sip._tcp.example.com` |
| PTR | रिवर्स लुकअप (IP → domain) | `34.216.184.93 → example.com` |

---

## SSH पोर्ट फॉरवर्डिंग

SSH के ज़रिए ट्रैफिक टनल करें। फायरवॉल के पीछे की सर्विसेज़ एक्सेस करने के लिए ज़रूरी।

```bash
# लोकल फॉरवर्डिंग: remote_host:3306 को localhost:9906 से एक्सेस करें
ssh -L 9906:localhost:3306 user@remote_host

# रिमोट फॉरवर्डिंग: अपना localhost:3000 रिमोट:8080 पर एक्सपोज़ करें
ssh -R 8080:localhost:3000 user@remote_host

# डायनामिक फॉरवर्डिंग (localhost:1080 पर SOCKS प्रॉक्सी)
ssh -D 1080 user@remote_host

# जंप होस्ट के ज़रिए टनल करें
ssh -J jump_host user@final_host
```

---

## त्वरित संदर्भ तालिका

| क्या | कमांड / मान |
|------|-----------------|
| खुले पोर्ट चेक करें | `ss -tlnp` या `netstat -tlnp` |
| पोर्ट स्कैन करें | `nmap -sV target` |
| DNS लुकअप | `dig example.com A` या `nslookup example.com` |
| रूट ट्रेस करें | `traceroute example.com` |
| कनेक्टिविटी टेस्ट करें | `ping -c 4 example.com` |
| HTTP रिक्वेस्ट | `curl -I https://example.com` |
| TLS सर्टिफिकेट चेक करें | `openssl s_client -connect example.com:443` |
| पैकेट कैप्चर करें | `tcpdump -i eth0 port 80` |
