---
title: "La Carte d'Internet : Ports Réseau, Protocoles et Codes de Statut"
description: "Guide visuel de TCP/IP, Modèle OSI, Ports Courants (SSH, HTTP, DNS) et Codes de Statut HTTP pour DevOps et Hackers."
date: 2026-02-13
tags: ["networking", "cheatsheet", "devops", "security", "sysadmin"]
keywords: ["common ports cheat sheet", "http status codes", "tcp vs udp", "osi model explained", "dns records types", "ssh port forwarding"]
draft: false
proficiency: "Intermediate"
aliases: ["/cheatsheets/networking-ports-protocols/"]
---

## Ports Courants

Chaque service sur un réseau écoute sur un port. Voici ceux que vous devez connaître par cœur.

### Ports Bien Connus (0–1023)

| Port | Protocole | Service | Notes |
|------|-----------|---------|-------|
| 20 | TCP | FTP Data | Transfert de données en mode actif |
| 21 | TCP | FTP Control | Commandes et authentification |
| 22 | TCP | SSH / SFTP | Shell sécurisé et transfert de fichiers |
| 23 | TCP | Telnet | Accès distant non chiffré (à éviter) |
| 25 | TCP | SMTP | Envoi d'emails |
| 53 | TCP/UDP | DNS | Résolution de noms de domaine |
| 67/68 | UDP | DHCP | Attribution dynamique d'adresses IP |
| 80 | TCP | HTTP | Trafic web non chiffré |
| 110 | TCP | POP3 | Récupération d'emails |
| 143 | TCP | IMAP | Récupération d'emails (côté serveur) |
| 443 | TCP | HTTPS | Trafic web chiffré (TLS) |
| 445 | TCP | SMB | Partage de fichiers Windows |
| 587 | TCP | SMTP (TLS) | Soumission sécurisée d'emails |

### Ports Enregistrés (1024–49151)

| Port | Protocole | Service | Notes |
|------|-----------|---------|-------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Listener Oracle database |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 3389 | TCP | RDP | Protocole Bureau à Distance |
| 5432 | TCP | PostgreSQL | Base de données PostgreSQL |
| 5900 | TCP | VNC | Virtual Network Computing |
| 6379 | TCP | Redis | Stockage de données en mémoire |
| 8080 | TCP | HTTP Alt | Port courant dev/proxy |
| 8443 | TCP | HTTPS Alt | Port HTTPS alternatif |
| 27017 | TCP | MongoDB | Base de données MongoDB |

---

## Codes de Statut HTTP

La façon dont le serveur vous dit ce qui s'est passé. Regroupés par catégorie.

### 1xx — Informationnel

| Code | Nom | Signification |
|------|-----|---------------|
| 100 | Continue | Continuez à envoyer le corps de la requête |
| 101 | Switching Protocols | Mise à niveau vers WebSocket |

### 2xx — Succès

| Code | Nom | Signification |
|------|-----|---------------|
| 200 | OK | La requête a réussi |
| 201 | Created | Ressource créée (succès POST) |
| 204 | No Content | Succès, mais rien à retourner |

### 3xx — Redirection

| Code | Nom | Signification |
|------|-----|---------------|
| 301 | Moved Permanently | URL modifiée définitivement (mettez à jour vos favoris) |
| 302 | Found | Redirection temporaire |
| 304 | Not Modified | Utilisez la version en cache |
| 307 | Temporary Redirect | Comme 302, mais conserve la méthode HTTP |
| 308 | Permanent Redirect | Comme 301, mais conserve la méthode HTTP |

### 4xx — Erreurs Client

| Code | Nom | Signification |
|------|-----|---------------|
| 400 | Bad Request | Syntaxe malformée ou données invalides |
| 401 | Unauthorized | Authentification requise |
| 403 | Forbidden | Authentifié mais non autorisé |
| 404 | Not Found | La ressource n'existe pas |
| 405 | Method Not Allowed | Mauvais verbe HTTP (GET vs POST) |
| 408 | Request Timeout | Le serveur en a assez d'attendre |
| 409 | Conflict | Conflit d'état (ex. doublon) |
| 413 | Payload Too Large | Le corps de la requête dépasse la limite |
| 418 | I'm a Teapot | RFC 2324. Oui, c'est réel. |
| 429 | Too Many Requests | Limite de débit atteinte |

### 5xx — Erreurs Serveur

| Code | Nom | Signification |
|------|-----|---------------|
| 500 | Internal Server Error | Erreur serveur générique |
| 502 | Bad Gateway | Le serveur en amont a envoyé une réponse invalide |
| 503 | Service Unavailable | Serveur surchargé ou en maintenance |
| 504 | Gateway Timeout | Le serveur en amont n'a pas répondu à temps |

---

## TCP vs UDP

Les deux protocoles de la couche transport. Des outils différents pour des usages différents.

| Caractéristique | TCP | UDP |
|-----------------|-----|-----|
| Connexion | Orienté connexion (handshake) | Sans connexion (envoyer et oublier) |
| Fiabilité | Livraison garantie, ordonnée | Aucune garantie, pas d'ordre |
| Vitesse | Plus lent (surcharge) | Plus rapide (surcharge minimale) |
| Taille de l'en-tête | 20–60 octets | 8 octets |
| Contrôle de flux | Oui (fenêtrage) | Non |
| Cas d'utilisation | Web, email, transfert de fichiers, SSH | DNS, streaming, jeux, VoIP |

### Poignée de Main TCP en Trois Étapes

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

## Poignée de main SSL/TLS

Comment HTTPS établit une connexion chiffrée.

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

Concepts clés :
- Le **chiffrement asymétrique** (RSA/ECDSA) est utilisé uniquement pour la poignée de main
- Le **chiffrement symétrique** (AES) est utilisé pour le transfert de données (plus rapide)
- **TLS 1.3** a réduit la poignée de main à 1 aller-retour (contre 2 pour TLS 1.2)

---

## Le modèle OSI

Sept couches, des câbles physiques à votre navigateur. Chaque couche communique avec son homologue à l'autre extrémité.

| Couche | Nom | Exemples de Protocoles | Unité de Données | Équipements |
|--------|-----|------------------------|------------------|-------------|
| 7 | Application | HTTP, FTP, DNS, SMTP | Données | — |
| 6 | Présentation | SSL/TLS, JPEG, ASCII | Données | — |
| 5 | Session | NetBIOS, RPC | Données | — |
| 4 | Transport | TCP, UDP | Segment/Datagramme | — |
| 3 | Réseau | IP, ICMP, ARP | Paquet | Routeur |
| 2 | Liaison de Données | Ethernet, Wi-Fi, PPP | Trame | Commutateur |
| 1 | Physique | Câbles, Radio, Fibre | Bits | Concentrateur |

> **Mnémotechnique (de haut en bas) :** **A**vec **P**lusieurs **S**ous-**T**asses, **N**ous **D**égustons des **P**âtisseries

### Modèle TCP/IP (Simplifié)

| Couche TCP/IP | Équivalent OSI | Exemples |
|---------------|----------------|----------|
| Application | 7, 6, 5 | HTTP, DNS, SSH |
| Transport | 4 | TCP, UDP |
| Internet | 3 | IP, ICMP |
| Accès Réseau | 2, 1 | Ethernet, Wi-Fi |

---

## Types d'Enregistrements DNS

Comment les noms de domaine sont associés aux services.

| Type | Objectif | Exemple |
|------|----------|---------|
| A | Domaine → IPv4 | `example.com → 93.184.216.34` |
| AAAA | Domaine → IPv6 | `example.com → 2606:2800:...` |
| CNAME | Alias vers un autre domaine | `www.example.com → example.com` |
| MX | Serveur de messagerie | `example.com → mail.example.com` |
| TXT | Vérification, SPF, DKIM | `v=spf1 include:_spf.google.com` |
| NS | Délégation de serveur de noms | `example.com → ns1.provider.com` |
| SOA | Info d'autorité de zone | Serial, refresh, retry, expire |
| SRV | Localisation de service | `_sip._tcp.example.com` |
| PTR | Recherche inversée (IP → domaine) | `34.216.184.93 → example.com` |

---

## Redirection de Ports SSH

Tunneliser le trafic via SSH. Essentiel pour accéder aux services derrière des pare-feu.

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

## Tableau de référence rapide

| Quoi | Commande / Valeur |
|------|-------------------|
| Vérifier les ports ouverts | `ss -tlnp` ou `netstat -tlnp` |
| Scanner les ports | `nmap -sV target` |
| Recherche DNS | `dig example.com A` ou `nslookup example.com` |
| Tracer la route | `traceroute example.com` |
| Tester la connectivité | `ping -c 4 example.com` |
| Requête HTTP | `curl -I https://example.com` |
| Vérifier le certificat TLS | `openssl s_client -connect example.com:443` |
| Capturer les paquets | `tcpdump -i eth0 port 80` |
