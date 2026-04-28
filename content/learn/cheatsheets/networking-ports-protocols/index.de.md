---
title: "Die Internet-Karte: Netzwerk-Ports, Protokolle und Statuscodes"
description: "Visueller Leitfaden zu TCP/IP, OSI-Modell, Gangige Ports (SSH, HTTP, DNS) und HTTP-Statuscodes fur DevOps und Hacker."
date: 2026-02-13
tags: ["networking", "cheatsheet", "devops", "security", "sysadmin"]
keywords: ["common ports cheat sheet", "http status codes", "tcp vs udp", "osi model explained", "dns records types", "ssh port forwarding"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Die Internet-Karte: Netzwerk-Ports, Protokolle und Statuscodes",
    "description": "Visueller Leitfaden zu TCP/IP, OSI-Modell, Gangige Ports (SSH, HTTP, DNS) und HTTP-Statuscodes fur DevOps und Hacker.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "de"
  }
---

## Gangige Ports

Jeder Dienst in einem Netzwerk lauscht auf einem Port. Diese sollten Sie auswendig kennen.

### Bekannte Ports (0–1023)

| Port | Protokoll | Dienst | Hinweise |
|------|-----------|--------|----------|
| 20 | TCP | FTP-Daten | Datentransfer im aktiven Modus |
| 21 | TCP | FTP-Steuerung | Befehle und Authentifizierung |
| 22 | TCP | SSH / SFTP | Sichere Shell und Dateitransfer |
| 23 | TCP | Telnet | Unverschlusselter Fernzugriff (vermeiden) |
| 25 | TCP | SMTP | E-Mail-Versand |
| 53 | TCP/UDP | DNS | Auflosung von Domainnamen |
| 67/68 | UDP | DHCP | Dynamische IP-Zuweisung |
| 80 | TCP | HTTP | Unverschlusselter Webverkehr |
| 110 | TCP | POP3 | E-Mail-Abruf |
| 143 | TCP | IMAP | E-Mail-Abruf (serverseitig) |
| 443 | TCP | HTTPS | Verschlusselter Webverkehr (TLS) |
| 445 | TCP | SMB | Windows-Dateifreigabe |
| 587 | TCP | SMTP (TLS) | Sicherer E-Mail-Versand |

### Registrierte Ports (1024–49151)

| Port | Protokoll | Dienst | Hinweise |
|------|-----------|--------|----------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Oracle-Datenbank-Listener |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 3389 | TCP | RDP | Remote Desktop Protocol |
| 5432 | TCP | PostgreSQL | PostgreSQL-Datenbank |
| 5900 | TCP | VNC | Virtual Network Computing |
| 6379 | TCP | Redis | In-Memory-Datenspeicher |
| 8080 | TCP | HTTP Alt | Haufiger Entwicklungs-/Proxy-Port |
| 8443 | TCP | HTTPS Alt | Alternativer HTTPS-Port |
| 27017 | TCP | MongoDB | MongoDB-Datenbank |

---

## HTTP-Statuscodes

Die Art des Servers, Ihnen mitzuteilen, was passiert ist. Nach Kategorie gruppiert.

### 1xx — Informativ

| Code | Name | Bedeutung |
|------|------|-----------|
| 100 | Continue | Senden Sie den Anfragekorper weiter |
| 101 | Switching Protocols | Upgrade auf WebSocket |

### 2xx — Erfolg

| Code | Name | Bedeutung |
|------|------|-----------|
| 200 | OK | Anfrage erfolgreich |
| 201 | Created | Ressource erstellt (POST erfolgreich) |
| 204 | No Content | Erfolgreich, aber nichts zuruckzugeben |

### 3xx — Weiterleitung

| Code | Name | Bedeutung |
|------|------|-----------|
| 301 | Moved Permanently | URL dauerhaft geandert (Lesezeichen aktualisieren) |
| 302 | Found | Temporare Weiterleitung |
| 304 | Not Modified | Gecachte Version verwenden |
| 307 | Temporary Redirect | Wie 302, aber HTTP-Methode beibehalten |
| 308 | Permanent Redirect | Wie 301, aber HTTP-Methode beibehalten |

### 4xx — Client-Fehler

| Code | Name | Bedeutung |
|------|------|-----------|
| 400 | Bad Request | Fehlerhafte Syntax oder ungultige Daten |
| 401 | Unauthorized | Authentifizierung erforderlich |
| 403 | Forbidden | Authentifiziert, aber nicht autorisiert |
| 404 | Not Found | Ressource existiert nicht |
| 405 | Method Not Allowed | Falsches HTTP-Verb (GET vs POST) |
| 408 | Request Timeout | Server hat zu lange gewartet |
| 409 | Conflict | Zustandskonflikt (z.B. Duplikat) |
| 413 | Payload Too Large | Anfragekorper uberschreitet Limit |
| 418 | I'm a Teapot | RFC 2324. Ja, das ist echt. |
| 429 | Too Many Requests | Ratenbegrenzung erreicht |

### 5xx — Server-Fehler

| Code | Name | Bedeutung |
|------|------|-----------|
| 500 | Internal Server Error | Allgemeiner Serverfehler |
| 502 | Bad Gateway | Upstream-Server sendete ungultige Antwort |
| 503 | Service Unavailable | Server uberlastet oder in Wartung |
| 504 | Gateway Timeout | Upstream-Server antwortete nicht rechtzeitig |

---

## TCP vs UDP

Die beiden Transportschicht-Protokolle. Unterschiedliche Werkzeuge fur unterschiedliche Aufgaben.

| Eigenschaft | TCP | UDP |
|-------------|-----|-----|
| Verbindung | Verbindungsorientiert (Handshake) | Verbindungslos (senden und vergessen) |
| Zuverlassigkeit | Garantierte Zustellung, geordnet | Keine Garantie, keine Reihenfolge |
| Geschwindigkeit | Langsamer (Overhead) | Schneller (minimaler Overhead) |
| Header-Grosse | 20–60 Bytes | 8 Bytes |
| Flusskontrolle | Ja (Windowing) | Nein |
| Anwendungsfalle | Web, E-Mail, Dateitransfer, SSH | DNS, Streaming, Gaming, VoIP |

### TCP Drei-Wege-Handshake

```
Client              Server
  |--- SYN ----------->|   1. Client sends SYN (seq=x)
  |<-- SYN-ACK --------|   2. Server replies SYN-ACK (seq=y, ack=x+1)
  |--- ACK ----------->|   3. Client sends ACK (ack=y+1)
  |                     |   Connection established
```

### TCP Verbindungsabbau

```
Client              Server
  |--- FIN ----------->|   1. Client initiates close
  |<-- ACK ------------|   2. Server acknowledges
  |<-- FIN ------------|   3. Server ready to close
  |--- ACK ----------->|   4. Client confirms
  |                     |   Connection closed
```

---

## SSL/TLS-Handshake

So stellt HTTPS eine verschlusselte Verbindung her.

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

Wichtige Konzepte:
- **Asymmetrische Verschlusselung** (RSA/ECDSA) wird nur fur den Handshake verwendet
- **Symmetrische Verschlusselung** (AES) wird fur den eigentlichen Datentransfer verwendet (schneller)
- **TLS 1.3** hat den Handshake auf 1 Roundtrip reduziert (statt 2 bei TLS 1.2)

---

## Das OSI-Modell

Sieben Schichten, von physischen Kabeln bis zu Ihrem Browser. Jede Schicht kommuniziert mit ihrem Gegenstuck auf der anderen Seite.

| Schicht | Name | Protokoll-Beispiele | Dateneinheit | Gerate |
|---------|------|---------------------|--------------|--------|
| 7 | Anwendung | HTTP, FTP, DNS, SMTP | Daten | — |
| 6 | Darstellung | SSL/TLS, JPEG, ASCII | Daten | — |
| 5 | Sitzung | NetBIOS, RPC | Daten | — |
| 4 | Transport | TCP, UDP | Segment/Datagramm | — |
| 3 | Vermittlung | IP, ICMP, ARP | Paket | Router |
| 2 | Sicherung | Ethernet, Wi-Fi, PPP | Frame | Switch |
| 1 | Bitubertragung | Kabel, Funk, Glasfaser | Bits | Hub |

> **Eselsbrucke (von oben nach unten):** **A**lle **D**eutschen **S**tudenten **T**rinken **V**erschiedene **S**orten **B**ier

### TCP/IP-Modell (Vereinfacht)

| TCP/IP-Schicht | OSI-Entsprechung | Beispiele |
|----------------|-------------------|-----------|
| Anwendung | 7, 6, 5 | HTTP, DNS, SSH |
| Transport | 4 | TCP, UDP |
| Internet | 3 | IP, ICMP |
| Netzzugang | 2, 1 | Ethernet, Wi-Fi |

---

## DNS-Eintragstypen

Wie Domainnamen auf Dienste abgebildet werden.

| Typ | Zweck | Beispiel |
|-----|-------|----------|
| A | Domain → IPv4 | `example.com → 93.184.216.34` |
| AAAA | Domain → IPv6 | `example.com → 2606:2800:...` |
| CNAME | Alias fur eine andere Domain | `www.example.com → example.com` |
| MX | Mailserver | `example.com → mail.example.com` |
| TXT | Verifizierung, SPF, DKIM | `v=spf1 include:_spf.google.com` |
| NS | Nameserver-Delegation | `example.com → ns1.provider.com` |
| SOA | Zonen-Autoritatsinformation | Serial, Refresh, Retry, Expire |
| SRV | Dienststandort | `_sip._tcp.example.com` |
| PTR | Reverse-Lookup (IP → Domain) | `34.216.184.93 → example.com` |

---

## SSH-Portweiterleitung

Datenverkehr durch SSH tunneln. Unverzichtbar fur den Zugriff auf Dienste hinter Firewalls.

```bash
# Local Forwarding: Zugriff auf remote_host:3306 uber localhost:9906
ssh -L 9906:localhost:3306 user@remote_host

# Remote Forwarding: Ihren localhost:3000 auf remote:8080 freigeben
ssh -R 8080:localhost:3000 user@remote_host

# Dynamic Forwarding (SOCKS-Proxy auf localhost:1080)
ssh -D 1080 user@remote_host

# Tunnel uber einen Jump-Host
ssh -J jump_host user@final_host
```

---

## Kurzreferenz-Tabelle

| Was | Befehl / Wert |
|-----|---------------|
| Offene Ports prufen | `ss -tlnp` oder `netstat -tlnp` |
| Ports scannen | `nmap -sV target` |
| DNS-Abfrage | `dig example.com A` oder `nslookup example.com` |
| Route verfolgen | `traceroute example.com` |
| Konnektivitat testen | `ping -c 4 example.com` |
| HTTP-Anfrage | `curl -I https://example.com` |
| TLS-Zertifikat prufen | `openssl s_client -connect example.com:443` |
| Pakete mitschneiden | `tcpdump -i eth0 port 80` |
