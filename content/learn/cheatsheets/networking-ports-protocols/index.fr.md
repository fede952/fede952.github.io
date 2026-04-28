---
title: "La Carte d'Internet : Ports Reseau, Protocoles et Codes de Statut"
description: "Guide visuel de TCP/IP, Modele OSI, Ports Courants (SSH, HTTP, DNS) et Codes de Statut HTTP pour DevOps et Hackers."
date: 2026-02-13
tags: ["networking", "cheatsheet", "devops", "security", "sysadmin"]
keywords: ["common ports cheat sheet", "http status codes", "tcp vs udp", "osi model explained", "dns records types", "ssh port forwarding"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "La Carte d'Internet : Ports Reseau, Protocoles et Codes de Statut",
    "description": "Guide visuel de TCP/IP, Modele OSI, Ports Courants (SSH, HTTP, DNS) et Codes de Statut HTTP pour DevOps et Hackers.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "fr"
  }
---

## Ports Courants

Chaque service sur un reseau ecoute sur un port. Voici ceux que vous devez connaitre par coeur.

### Ports Bien Connus (0–1023)

| Port | Protocole | Service | Notes |
|------|-----------|---------|-------|
| 20 | TCP | FTP Data | Transfert de donnees en mode actif |
| 21 | TCP | FTP Control | Commandes et authentification |
| 22 | TCP | SSH / SFTP | Shell securise et transfert de fichiers |
| 23 | TCP | Telnet | Acces distant non chiffre (a eviter) |
| 25 | TCP | SMTP | Envoi d'emails |
| 53 | TCP/UDP | DNS | Resolution de noms de domaine |
| 67/68 | UDP | DHCP | Attribution dynamique d'adresses IP |
| 80 | TCP | HTTP | Trafic web non chiffre |
| 110 | TCP | POP3 | Recuperation d'emails |
| 143 | TCP | IMAP | Recuperation d'emails (cote serveur) |
| 443 | TCP | HTTPS | Trafic web chiffre (TLS) |
| 445 | TCP | SMB | Partage de fichiers Windows |
| 587 | TCP | SMTP (TLS) | Soumission securisee d'emails |

### Ports Enregistres (1024–49151)

| Port | Protocole | Service | Notes |
|------|-----------|---------|-------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Listener Oracle database |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 3389 | TCP | RDP | Protocole Bureau a Distance |
| 5432 | TCP | PostgreSQL | Base de donnees PostgreSQL |
| 5900 | TCP | VNC | Virtual Network Computing |
| 6379 | TCP | Redis | Stockage de donnees en memoire |
| 8080 | TCP | HTTP Alt | Port courant dev/proxy |
| 8443 | TCP | HTTPS Alt | Port HTTPS alternatif |
| 27017 | TCP | MongoDB | Base de donnees MongoDB |

---

## Codes de Statut HTTP

La facon dont le serveur vous dit ce qui s'est passe. Regroupes par categorie.

### 1xx — Informationnel

| Code | Nom | Signification |
|------|-----|---------------|
| 100 | Continue | Continuez a envoyer le corps de la requete |
| 101 | Switching Protocols | Mise a niveau vers WebSocket |

### 2xx — Succes

| Code | Nom | Signification |
|------|-----|---------------|
| 200 | OK | La requete a reussi |
| 201 | Created | Ressource creee (succes POST) |
| 204 | No Content | Succes, mais rien a retourner |

### 3xx — Redirection

| Code | Nom | Signification |
|------|-----|---------------|
| 301 | Moved Permanently | URL modifiee definitivement (mettez a jour vos favoris) |
| 302 | Found | Redirection temporaire |
| 304 | Not Modified | Utilisez la version en cache |
| 307 | Temporary Redirect | Comme 302, mais conserve la methode HTTP |
| 308 | Permanent Redirect | Comme 301, mais conserve la methode HTTP |

### 4xx — Erreurs Client

| Code | Nom | Signification |
|------|-----|---------------|
| 400 | Bad Request | Syntaxe malformee ou donnees invalides |
| 401 | Unauthorized | Authentification requise |
| 403 | Forbidden | Authentifie mais non autorise |
| 404 | Not Found | La ressource n'existe pas |
| 405 | Method Not Allowed | Mauvais verbe HTTP (GET vs POST) |
| 408 | Request Timeout | Le serveur en a assez d'attendre |
| 409 | Conflict | Conflit d'etat (ex. doublon) |
| 413 | Payload Too Large | Le corps de la requete depasse la limite |
| 418 | I'm a Teapot | RFC 2324. Oui, c'est reel. |
| 429 | Too Many Requests | Limite de debit atteinte |

### 5xx — Erreurs Serveur

| Code | Nom | Signification |
|------|-----|---------------|
| 500 | Internal Server Error | Erreur serveur generique |
| 502 | Bad Gateway | Le serveur en amont a envoye une reponse invalide |
| 503 | Service Unavailable | Serveur surcharge ou en maintenance |
| 504 | Gateway Timeout | Le serveur en amont n'a pas repondu a temps |

---

## TCP vs UDP

Les deux protocoles de la couche transport. Des outils differents pour des usages differents.

| Caracteristique | TCP | UDP |
|-----------------|-----|-----|
| Connexion | Oriente connexion (handshake) | Sans connexion (envoyer et oublier) |
| Fiabilite | Livraison garantie, ordonnee | Aucune garantie, pas d'ordre |
| Vitesse | Plus lent (surcharge) | Plus rapide (surcharge minimale) |
| Taille de l'en-tete | 20–60 octets | 8 octets |
| Controle de flux | Oui (fenetrage) | Non |
| Cas d'utilisation | Web, email, transfert de fichiers, SSH | DNS, streaming, jeux, VoIP |

### Poignee de Main TCP en Trois Etapes

```
Client              Server
  |--- SYN ----------->|   1. Client sends SYN (seq=x)
  |<-- SYN-ACK --------|   2. Server replies SYN-ACK (seq=y, ack=x+1)
  |--- ACK ----------->|   3. Client sends ACK (ack=y+1)
  |                     |   Connection established
```

### Fermeture de Connexion TCP

```
Client              Server
  |--- FIN ----------->|   1. Client initiates close
  |<-- ACK ------------|   2. Server acknowledges
  |<-- FIN ------------|   3. Server ready to close
  |--- ACK ----------->|   4. Client confirms
  |                     |   Connection closed
```

---

## Poignee de Main SSL/TLS

Comment HTTPS etablit une connexion chiffree.

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

Concepts cles :
- Le **chiffrement asymetrique** (RSA/ECDSA) est utilise uniquement pour la poignee de main
- Le **chiffrement symetrique** (AES) est utilise pour le transfert de donnees (plus rapide)
- **TLS 1.3** a reduit la poignee de main a 1 aller-retour (contre 2 pour TLS 1.2)

---

## Le Modele OSI

Sept couches, des cables physiques a votre navigateur. Chaque couche communique avec son homologue a l'autre extremite.

| Couche | Nom | Exemples de Protocoles | Unite de Donnees | Equipements |
|--------|-----|------------------------|------------------|-------------|
| 7 | Application | HTTP, FTP, DNS, SMTP | Donnees | — |
| 6 | Presentation | SSL/TLS, JPEG, ASCII | Donnees | — |
| 5 | Session | NetBIOS, RPC | Donnees | — |
| 4 | Transport | TCP, UDP | Segment/Datagramme | — |
| 3 | Reseau | IP, ICMP, ARP | Paquet | Routeur |
| 2 | Liaison de Donnees | Ethernet, Wi-Fi, PPP | Trame | Commutateur |
| 1 | Physique | Cables, Radio, Fibre | Bits | Concentrateur |

> **Mnemotechnique (de haut en bas) :** **A**vec **P**lusieurs **S**ous-**T**asses, **N**ous **D**egustons des **P**atisseries

### Modele TCP/IP (Simplifie)

| Couche TCP/IP | Equivalent OSI | Exemples |
|---------------|----------------|----------|
| Application | 7, 6, 5 | HTTP, DNS, SSH |
| Transport | 4 | TCP, UDP |
| Internet | 3 | IP, ICMP |
| Acces Reseau | 2, 1 | Ethernet, Wi-Fi |

---

## Types d'Enregistrements DNS

Comment les noms de domaine sont associes aux services.

| Type | Objectif | Exemple |
|------|----------|---------|
| A | Domaine → IPv4 | `example.com → 93.184.216.34` |
| AAAA | Domaine → IPv6 | `example.com → 2606:2800:...` |
| CNAME | Alias vers un autre domaine | `www.example.com → example.com` |
| MX | Serveur de messagerie | `example.com → mail.example.com` |
| TXT | Verification, SPF, DKIM | `v=spf1 include:_spf.google.com` |
| NS | Delegation de serveur de noms | `example.com → ns1.provider.com` |
| SOA | Info d'autorite de zone | Serial, refresh, retry, expire |
| SRV | Localisation de service | `_sip._tcp.example.com` |
| PTR | Recherche inversee (IP → domaine) | `34.216.184.93 → example.com` |

---

## Redirection de Ports SSH

Tunneliser le trafic via SSH. Essentiel pour acceder aux services derriere des pare-feu.

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

## Tableau de Reference Rapide

| Quoi | Commande / Valeur |
|------|-------------------|
| Verifier les ports ouverts | `ss -tlnp` ou `netstat -tlnp` |
| Scanner les ports | `nmap -sV target` |
| Recherche DNS | `dig example.com A` ou `nslookup example.com` |
| Tracer la route | `traceroute example.com` |
| Tester la connectivite | `ping -c 4 example.com` |
| Requete HTTP | `curl -I https://example.com` |
| Verifier le certificat TLS | `openssl s_client -connect example.com:443` |
| Capturer les paquets | `tcpdump -i eth0 port 80` |
