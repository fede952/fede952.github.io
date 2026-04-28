---
title: "La Mappa di Internet: Porte di Rete, Protocolli e Codici di Stato"
description: "Guida visuale a TCP/IP, Modello OSI, Porte Comuni (SSH, HTTP, DNS) e Codici di Stato HTTP per DevOps e Hacker."
date: 2026-02-13
tags: ["networking", "cheatsheet", "devops", "security", "sysadmin"]
keywords: ["common ports cheat sheet", "http status codes", "tcp vs udp", "osi model explained", "dns records types", "ssh port forwarding"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "La Mappa di Internet: Porte di Rete, Protocolli e Codici di Stato",
    "description": "Guida visuale a TCP/IP, Modello OSI, Porte Comuni (SSH, HTTP, DNS) e Codici di Stato HTTP per DevOps e Hacker.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "it"
  }
---

## Porte Comuni

Ogni servizio in una rete ascolta su una porta. Queste sono quelle che devi conoscere a memoria.

### Porte Note (0–1023)

| Porta | Protocollo | Servizio | Note |
|-------|------------|----------|------|
| 20 | TCP | FTP Data | Trasferimento dati in modalita attiva |
| 21 | TCP | FTP Control | Comandi e autenticazione |
| 22 | TCP | SSH / SFTP | Shell sicura e trasferimento file |
| 23 | TCP | Telnet | Accesso remoto non criptato (da evitare) |
| 25 | TCP | SMTP | Invio email |
| 53 | TCP/UDP | DNS | Risoluzione nomi di dominio |
| 67/68 | UDP | DHCP | Assegnazione IP dinamica |
| 80 | TCP | HTTP | Traffico web non criptato |
| 110 | TCP | POP3 | Ricezione email |
| 143 | TCP | IMAP | Ricezione email (lato server) |
| 443 | TCP | HTTPS | Traffico web criptato (TLS) |
| 445 | TCP | SMB | Condivisione file Windows |
| 587 | TCP | SMTP (TLS) | Invio email sicuro |

### Porte Registrate (1024–49151)

| Porta | Protocollo | Servizio | Note |
|-------|------------|----------|------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Listener database Oracle |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 3389 | TCP | RDP | Remote Desktop Protocol |
| 5432 | TCP | PostgreSQL | Database PostgreSQL |
| 5900 | TCP | VNC | Virtual Network Computing |
| 6379 | TCP | Redis | Archivio dati in memoria |
| 8080 | TCP | HTTP Alt | Porta comune per sviluppo/proxy |
| 8443 | TCP | HTTPS Alt | Porta HTTPS alternativa |
| 27017 | TCP | MongoDB | Database MongoDB |

---

## Codici di Stato HTTP

Il modo in cui il server ti dice cosa e successo. Raggruppati per categoria.

### 1xx — Informativi

| Codice | Nome | Significato |
|--------|------|-------------|
| 100 | Continue | Continua a inviare il corpo della richiesta |
| 101 | Switching Protocols | Aggiornamento a WebSocket |

### 2xx — Successo

| Codice | Nome | Significato |
|--------|------|-------------|
| 200 | OK | Richiesta riuscita |
| 201 | Created | Risorsa creata (POST riuscito) |
| 204 | No Content | Successo, ma nulla da restituire |

### 3xx — Reindirizzamento

| Codice | Nome | Significato |
|--------|------|-------------|
| 301 | Moved Permanently | URL cambiato per sempre (aggiorna i segnalibri) |
| 302 | Found | Reindirizzamento temporaneo |
| 304 | Not Modified | Usa la versione in cache |
| 307 | Temporary Redirect | Come 302, ma mantieni il metodo HTTP |
| 308 | Permanent Redirect | Come 301, ma mantieni il metodo HTTP |

### 4xx — Errori del Client

| Codice | Nome | Significato |
|--------|------|-------------|
| 400 | Bad Request | Sintassi malformata o dati non validi |
| 401 | Unauthorized | Autenticazione richiesta |
| 403 | Forbidden | Autenticato ma non autorizzato |
| 404 | Not Found | La risorsa non esiste |
| 405 | Method Not Allowed | Verbo HTTP sbagliato (GET vs POST) |
| 408 | Request Timeout | Il server si e stancato di aspettare |
| 409 | Conflict | Conflitto di stato (es. duplicato) |
| 413 | Payload Too Large | Il corpo della richiesta supera il limite |
| 418 | I'm a Teapot | RFC 2324. Si, esiste davvero. |
| 429 | Too Many Requests | Limite di frequenza raggiunto |

### 5xx — Errori del Server

| Codice | Nome | Significato |
|--------|------|-------------|
| 500 | Internal Server Error | Errore generico del server |
| 502 | Bad Gateway | Il server upstream ha inviato una risposta non valida |
| 503 | Service Unavailable | Server sovraccarico o in manutenzione |
| 504 | Gateway Timeout | Il server upstream non ha risposto in tempo |

---

## TCP vs UDP

I due protocolli del livello di trasporto. Strumenti diversi per lavori diversi.

| Caratteristica | TCP | UDP |
|----------------|-----|-----|
| Connessione | Orientato alla connessione (handshake) | Senza connessione (invia e dimentica) |
| Affidabilita | Consegna garantita, ordinata | Nessuna garanzia, nessun ordine |
| Velocita | Piu lento (overhead) | Piu veloce (overhead minimo) |
| Dimensione header | 20–60 byte | 8 byte |
| Controllo di flusso | Si (windowing) | No |
| Casi d'uso | Web, email, trasferimento file, SSH | DNS, streaming, gaming, VoIP |

### Handshake a Tre Vie TCP

```
Client              Server
  |--- SYN ----------->|   1. Client sends SYN (seq=x)
  |<-- SYN-ACK --------|   2. Server replies SYN-ACK (seq=y, ack=x+1)
  |--- ACK ----------->|   3. Client sends ACK (ack=y+1)
  |                     |   Connection established
```

### Chiusura della Connessione TCP

```
Client              Server
  |--- FIN ----------->|   1. Client initiates close
  |<-- ACK ------------|   2. Server acknowledges
  |<-- FIN ------------|   3. Server ready to close
  |--- ACK ----------->|   4. Client confirms
  |                     |   Connection closed
```

---

## Handshake SSL/TLS

Come HTTPS stabilisce una connessione criptata.

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

Concetti chiave:
- La **crittografia asimmetrica** (RSA/ECDSA) viene usata solo per l'handshake
- La **crittografia simmetrica** (AES) viene usata per il trasferimento dati effettivo (piu veloce)
- **TLS 1.3** ha ridotto l'handshake a 1 round-trip (contro i 2 di TLS 1.2)

---

## Il Modello OSI

Sette livelli, dai cavi fisici al tuo browser. Ogni livello comunica con il suo pari dall'altra parte.

| Livello | Nome | Esempi di Protocollo | Unita Dati | Dispositivi |
|---------|------|----------------------|------------|-------------|
| 7 | Applicazione | HTTP, FTP, DNS, SMTP | Dati | — |
| 6 | Presentazione | SSL/TLS, JPEG, ASCII | Dati | — |
| 5 | Sessione | NetBIOS, RPC | Dati | — |
| 4 | Trasporto | TCP, UDP | Segmento/Datagramma | — |
| 3 | Rete | IP, ICMP, ARP | Pacchetto | Router |
| 2 | Collegamento Dati | Ethernet, Wi-Fi, PPP | Frame | Switch |
| 1 | Fisico | Cavi, Radio, Fibra | Bit | Hub |

> **Mnemonico (dall'alto in basso):** **A**ll **P**eople **S**eem **T**o **N**eed **D**ata **P**rocessing

### Modello TCP/IP (Semplificato)

| Livello TCP/IP | Equivalente OSI | Esempi |
|----------------|-----------------|--------|
| Applicazione | 7, 6, 5 | HTTP, DNS, SSH |
| Trasporto | 4 | TCP, UDP |
| Internet | 3 | IP, ICMP |
| Accesso alla Rete | 2, 1 | Ethernet, Wi-Fi |

---

## Tipi di Record DNS

Come i nomi di dominio vengono mappati ai servizi.

| Tipo | Scopo | Esempio |
|------|-------|---------|
| A | Dominio → IPv4 | `example.com → 93.184.216.34` |
| AAAA | Dominio → IPv6 | `example.com → 2606:2800:...` |
| CNAME | Alias verso un altro dominio | `www.example.com → example.com` |
| MX | Server di posta | `example.com → mail.example.com` |
| TXT | Verifica, SPF, DKIM | `v=spf1 include:_spf.google.com` |
| NS | Delega del nameserver | `example.com → ns1.provider.com` |
| SOA | Info autorita della zona | Serial, refresh, retry, expire |
| SRV | Localizzazione del servizio | `_sip._tcp.example.com` |
| PTR | Ricerca inversa (IP → dominio) | `34.216.184.93 → example.com` |

---

## Port Forwarding SSH

Instrada il traffico attraverso SSH. Essenziale per accedere a servizi dietro firewall.

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

## Tabella di Riferimento Rapido

| Cosa | Comando / Valore |
|------|------------------|
| Controllare le porte aperte | `ss -tlnp` o `netstat -tlnp` |
| Scansionare le porte | `nmap -sV target` |
| Ricerca DNS | `dig example.com A` o `nslookup example.com` |
| Tracciare il percorso | `traceroute example.com` |
| Testare la connettivita | `ping -c 4 example.com` |
| Richiesta HTTP | `curl -I https://example.com` |
| Controllare il certificato TLS | `openssl s_client -connect example.com:443` |
| Catturare pacchetti | `tcpdump -i eth0 port 80` |
