---
title: "The Internet Map: Networking Ports, Protocols & Status Codes"
description: "Visual guide to TCP/IP, OSI Model, Common Ports (SSH, HTTP, DNS), and HTTP Status Codes for DevOps and Hackers."
date: 2026-02-13
tags: ["networking", "cheatsheet", "devops", "security", "sysadmin"]
keywords: ["common ports cheat sheet", "http status codes", "tcp vs udp", "osi model explained", "dns records types", "ssh port forwarding"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "The Internet Map: Networking Ports, Protocols & Status Codes",
    "description": "Visual guide to TCP/IP, OSI Model, Common Ports (SSH, HTTP, DNS), and HTTP Status Codes for DevOps and Hackers.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "en"
  }
---

## Common Ports

Every service on a network listens on a port. These are the ones you need to know by heart.

### Well-Known Ports (0–1023)

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 20 | TCP | FTP Data | Active mode data transfer |
| 21 | TCP | FTP Control | Commands and authentication |
| 22 | TCP | SSH / SFTP | Secure shell and file transfer |
| 23 | TCP | Telnet | Unencrypted remote access (avoid) |
| 25 | TCP | SMTP | Email sending |
| 53 | TCP/UDP | DNS | Domain name resolution |
| 67/68 | UDP | DHCP | Dynamic IP assignment |
| 80 | TCP | HTTP | Unencrypted web traffic |
| 110 | TCP | POP3 | Email retrieval |
| 143 | TCP | IMAP | Email retrieval (server-side) |
| 443 | TCP | HTTPS | Encrypted web traffic (TLS) |
| 445 | TCP | SMB | Windows file sharing |
| 587 | TCP | SMTP (TLS) | Secure email submission |

### Registered Ports (1024–49151)

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Oracle database listener |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 3389 | TCP | RDP | Remote Desktop Protocol |
| 5432 | TCP | PostgreSQL | PostgreSQL database |
| 5900 | TCP | VNC | Virtual Network Computing |
| 6379 | TCP | Redis | In-memory data store |
| 8080 | TCP | HTTP Alt | Common dev/proxy port |
| 8443 | TCP | HTTPS Alt | Alternative HTTPS port |
| 27017 | TCP | MongoDB | MongoDB database |

---

## HTTP Status Codes

The server's way of telling you what happened. Grouped by category.

### 1xx — Informational

| Code | Name | Meaning |
|------|------|---------|
| 100 | Continue | Keep sending the request body |
| 101 | Switching Protocols | Upgrading to WebSocket |

### 2xx — Success

| Code | Name | Meaning |
|------|------|---------|
| 200 | OK | Request succeeded |
| 201 | Created | Resource created (POST success) |
| 204 | No Content | Success, but nothing to return |

### 3xx — Redirection

| Code | Name | Meaning |
|------|------|---------|
| 301 | Moved Permanently | URL changed forever (update bookmarks) |
| 302 | Found | Temporary redirect |
| 304 | Not Modified | Use cached version |
| 307 | Temporary Redirect | Like 302, but keep HTTP method |
| 308 | Permanent Redirect | Like 301, but keep HTTP method |

### 4xx — Client Errors

| Code | Name | Meaning |
|------|------|---------|
| 400 | Bad Request | Malformed syntax or invalid data |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Authenticated but not authorized |
| 404 | Not Found | Resource doesn't exist |
| 405 | Method Not Allowed | Wrong HTTP verb (GET vs POST) |
| 408 | Request Timeout | Server tired of waiting |
| 409 | Conflict | State conflict (e.g., duplicate) |
| 413 | Payload Too Large | Request body exceeds limit |
| 418 | I'm a Teapot | RFC 2324. Yes, it's real. |
| 429 | Too Many Requests | Rate limited |

### 5xx — Server Errors

| Code | Name | Meaning |
|------|------|---------|
| 500 | Internal Server Error | Generic server failure |
| 502 | Bad Gateway | Upstream server sent invalid response |
| 503 | Service Unavailable | Server overloaded or in maintenance |
| 504 | Gateway Timeout | Upstream server didn't respond in time |

---

## TCP vs UDP

The two transport layer protocols. Different tools for different jobs.

| Feature | TCP | UDP |
|---------|-----|-----|
| Connection | Connection-oriented (handshake) | Connectionless (fire and forget) |
| Reliability | Guaranteed delivery, ordered | No guarantee, no ordering |
| Speed | Slower (overhead) | Faster (minimal overhead) |
| Header size | 20–60 bytes | 8 bytes |
| Flow control | Yes (windowing) | No |
| Use cases | Web, email, file transfer, SSH | DNS, streaming, gaming, VoIP |

### TCP Three-Way Handshake

```
Client              Server
  |--- SYN ----------->|   1. Client sends SYN (seq=x)
  |<-- SYN-ACK --------|   2. Server replies SYN-ACK (seq=y, ack=x+1)
  |--- ACK ----------->|   3. Client sends ACK (ack=y+1)
  |                     |   Connection established
```

### TCP Connection Teardown

```
Client              Server
  |--- FIN ----------->|   1. Client initiates close
  |<-- ACK ------------|   2. Server acknowledges
  |<-- FIN ------------|   3. Server ready to close
  |--- ACK ----------->|   4. Client confirms
  |                     |   Connection closed
```

---

## SSL/TLS Handshake

How HTTPS establishes an encrypted connection.

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

Key concepts:
- **Asymmetric encryption** (RSA/ECDSA) is used only for the handshake
- **Symmetric encryption** (AES) is used for actual data transfer (faster)
- **TLS 1.3** reduced the handshake to 1 round-trip (vs 2 in TLS 1.2)

---

## The OSI Model

Seven layers, from physical cables to your browser. Each layer talks to its peer on the other end.

| Layer | Name | Protocol Examples | Data Unit | Devices |
|-------|------|-------------------|-----------|---------|
| 7 | Application | HTTP, FTP, DNS, SMTP | Data | — |
| 6 | Presentation | SSL/TLS, JPEG, ASCII | Data | — |
| 5 | Session | NetBIOS, RPC | Data | — |
| 4 | Transport | TCP, UDP | Segment/Datagram | — |
| 3 | Network | IP, ICMP, ARP | Packet | Router |
| 2 | Data Link | Ethernet, Wi-Fi, PPP | Frame | Switch |
| 1 | Physical | Cables, Radio, Fiber | Bits | Hub |

> **Mnemonic (top to bottom):** **A**ll **P**eople **S**eem **T**o **N**eed **D**ata **P**rocessing

### TCP/IP Model (Simplified)

| TCP/IP Layer | OSI Equivalent | Examples |
|--------------|----------------|----------|
| Application | 7, 6, 5 | HTTP, DNS, SSH |
| Transport | 4 | TCP, UDP |
| Internet | 3 | IP, ICMP |
| Network Access | 2, 1 | Ethernet, Wi-Fi |

---

## DNS Record Types

How domain names map to services.

| Type | Purpose | Example |
|------|---------|---------|
| A | Domain → IPv4 | `example.com → 93.184.216.34` |
| AAAA | Domain → IPv6 | `example.com → 2606:2800:...` |
| CNAME | Alias to another domain | `www.example.com → example.com` |
| MX | Mail server | `example.com → mail.example.com` |
| TXT | Verification, SPF, DKIM | `v=spf1 include:_spf.google.com` |
| NS | Nameserver delegation | `example.com → ns1.provider.com` |
| SOA | Zone authority info | Serial, refresh, retry, expire |
| SRV | Service location | `_sip._tcp.example.com` |
| PTR | Reverse lookup (IP → domain) | `34.216.184.93 → example.com` |

---

## SSH Port Forwarding

Tunnel traffic through SSH. Essential for accessing services behind firewalls.

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

## Quick Reference Table

| What | Command / Value |
|------|-----------------|
| Check open ports | `ss -tlnp` or `netstat -tlnp` |
| Scan ports | `nmap -sV target` |
| DNS lookup | `dig example.com A` or `nslookup example.com` |
| Trace route | `traceroute example.com` |
| Test connectivity | `ping -c 4 example.com` |
| HTTP request | `curl -I https://example.com` |
| Check TLS cert | `openssl s_client -connect example.com:443` |
| Capture packets | `tcpdump -i eth0 port 80` |
