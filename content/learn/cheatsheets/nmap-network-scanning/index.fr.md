---
title: "Manuel de Terrain Nmap : Commandes de Reconnaissance Réseau"
description: "Commandes essentielles Nmap pour l'analyse réseau, la découverte d'hôtes, l'énumération de ports, la détection de services et l'évaluation des vulnérabilités. Une référence tactique rapide pour les pentesters."
date: 2026-02-10
tags: ["nmap", "cheatsheet", "penetration-testing", "network-security", "reconnaissance"]
keywords: ["nmap cheatsheet", "commandes nmap", "guide analyse réseau", "nmap scan de ports", "nmap détection de services", "nmap scripts NSE", "nmap scan de vulnérabilités", "commandes penetration testing"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Manuel de Terrain Nmap : Commandes de Reconnaissance Réseau",
    "description": "Commandes essentielles Nmap pour l'analyse réseau, la découverte d'hôtes, l'énumération de ports et l'évaluation des vulnérabilités.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "fr"
  }
---

## $ System_Init

Nmap est le premier outil chargé dans toute activité de reconnaissance. Il cartographie la surface d'attaque, identifie les hôtes actifs, énumère les ports ouverts, identifie les services et détecte les vulnérabilités — le tout depuis un seul binaire. Ce manuel de terrain fournit les commandes exactes pour chaque phase de la reconnaissance réseau.

Toutes les commandes supposent des tests autorisés. Déployer de manière responsable.

---

## $ Host_Discovery

Identifier les cibles actives sur le réseau avant l'analyse des ports.

### Balayage ping (ICMP echo)

```bash
# Découvrir les hôtes actifs sur un sous-réseau en utilisant le ping ICMP
nmap -sn 192.168.1.0/24
```

### Découverte ARP (réseau local uniquement)

```bash
# Utiliser les requêtes ARP pour la découverte d'hôtes sur le LAN local (méthode la plus rapide)
nmap -sn -PR 192.168.1.0/24
```

### Découverte TCP SYN sur des ports spécifiques

```bash
# Découvrir les hôtes en envoyant des paquets SYN aux ports courants
nmap -sn -PS22,80,443 10.0.0.0/24
```

### Désactiver la résolution DNS (accélérer les scans)

```bash
# Ignorer les recherches DNS inversées pour des résultats plus rapides
nmap -sn -n 192.168.1.0/24
```

### Scan de liste (aucun paquet envoyé)

```bash
# Lister les cibles qui seraient scannées sans envoyer de paquets
nmap -sL 192.168.1.0/24
```

---

## $ Port_Scanning

Énumérer les ports ouverts pour cartographier la surface d'attaque de la cible.

### Scan SYN (scan furtif — par défaut)

```bash
# Scan semi-ouvert : envoie SYN, reçoit SYN/ACK, envoie RST (ne complète jamais le handshake)
sudo nmap -sS 192.168.1.100
```

### Scan TCP connect (ne nécessite pas root)

```bash
# Scan complet avec handshake TCP (plus lent mais fonctionne sans privilèges élevés)
nmap -sT 192.168.1.100
```

### Scan UDP

```bash
# Scanner les ports UDP ouverts (plus lent en raison du comportement du protocole)
sudo nmap -sU 192.168.1.100
```

### Scanner des ports spécifiques

```bash
# Scanner uniquement des ports spécifiques
nmap -p 22,80,443,8080 192.168.1.100

# Scanner une plage de ports
nmap -p 1-1024 192.168.1.100

# Scanner tous les 65535 ports
nmap -p- 192.168.1.100
```

### Scan des ports principaux

```bash
# Scanner les 100 ports les plus couramment ouverts
nmap --top-ports 100 192.168.1.100
```

### Scan rapide (top 100 ports)

```bash
# Scan rapide avec un nombre réduit de ports pour une évaluation rapide
nmap -F 192.168.1.100
```

---

## $ Service_Detection

Identifier quel logiciel s'exécute sur chaque port ouvert.

### Détection de version

```bash
# Sonder les ports ouverts pour déterminer le nom et la version du service
nmap -sV 192.168.1.100
```

### Détection de version agressive

```bash
# Augmenter l'intensité de détection (1-9, par défaut 7)
nmap -sV --version-intensity 9 192.168.1.100
```

### Empreinte du système d'exploitation

```bash
# Détecter le système d'exploitation de la cible en utilisant l'analyse de la pile TCP/IP
sudo nmap -O 192.168.1.100
```

### Détection combinée service + OS

```bash
# Énumération complète des services avec empreinte du système d'exploitation
sudo nmap -sV -O 192.168.1.100
```

### Scan agressif (OS + version + scripts + traceroute)

```bash
# Activer toutes les fonctionnalités de détection en un seul flag
sudo nmap -A 192.168.1.100
```

---

## $ NSE_Scripts

Nmap Scripting Engine — détection automatique des vulnérabilités et énumération.

### Exécuter les scripts par défaut

```bash
# Exécuter l'ensemble par défaut de scripts sûrs et informatifs
nmap -sC 192.168.1.100
```

### Exécuter un script spécifique

```bash
# Exécuter un seul script NSE par nom
nmap --script=http-title 192.168.1.100
```

### Exécuter des catégories de scripts

```bash
# Exécuter tous les scripts de détection de vulnérabilités
nmap --script=vuln 192.168.1.100

# Exécuter tous les scripts de découverte
nmap --script=discovery 192.168.1.100

# Exécuter les scripts de force brute contre les services d'authentification
nmap --script=brute 192.168.1.100
```

### Énumération HTTP

```bash
# Énumérer les répertoires et fichiers du serveur web
nmap --script=http-enum 192.168.1.100

# Détecter les pare-feu d'applications web
nmap --script=http-waf-detect 192.168.1.100
```

### Énumération SMB

```bash
# Énumérer les partages SMB et les utilisateurs (réseaux Windows)
nmap --script=smb-enum-shares,smb-enum-users 192.168.1.100
```

### Analyse SSL/TLS

```bash
# Vérifier les détails du certificat SSL et les suites de chiffrement
nmap --script=ssl-cert,ssl-enum-ciphers -p 443 192.168.1.100
```

---

## $ Evasion_Techniques

Contourner les pare-feu et IDS lors de tests d'intrusion autorisés.

### Fragmenter les paquets

```bash
# Diviser les paquets de sonde en fragments plus petits pour contourner les filtres de paquets simples
sudo nmap -f 192.168.1.100
```

### Scan leurre

```bash
# Générer des adresses IP sources falsifiées pour masquer le vrai scanner
sudo nmap -D RND:10 192.168.1.100
```

### Usurper le port source

```bash
# Utiliser un port source de confiance pour contourner les règles de pare-feu basées sur les ports
sudo nmap --source-port 53 192.168.1.100
```

### Contrôle de la temporisation

```bash
# T0=Paranoid, T1=Sneaky, T2=Polite, T3=Normal, T4=Aggressive, T5=Insane
nmap -T2 192.168.1.100
```

### Scan inactif (scan zombie)

```bash
# Utiliser un hôte "zombie" tiers pour scanner sans révéler votre IP
sudo nmap -sI zombie-host.com 192.168.1.100
```

---

## $ Output_Formats

Sauvegarder les résultats du scan pour la documentation et le post-traitement.

### Sortie normale

```bash
# Sauvegarder les résultats dans un format lisible par l'homme
nmap -oN scan_results.txt 192.168.1.100
```

### Sortie XML (pour les outils)

```bash
# Sauvegarder les résultats au format XML (analysable par Metasploit, etc.)
nmap -oX scan_results.xml 192.168.1.100
```

### Sortie grep-able

```bash
# Sauvegarder les résultats dans un format compatible avec grep pour le scripting
nmap -oG scan_results.gnmap 192.168.1.100
```

### Tous les formats à la fois

```bash
# Sauvegarder en format normal, XML et grep-able simultanément
nmap -oA full_scan 192.168.1.100
```

---

## $ Mission_Templates

Chaînes de commandes copier-coller pour des scénarios d'engagement courants.

### Reconnaissance rapide

```bash
# Évaluation initiale rapide d'une cible
nmap -sS -sV -F -T4 --open 192.168.1.100
```

### Scan complet des ports avec détection de services

```bash
# Scan complet de tous les ports avec détection de version
sudo nmap -sS -sV -p- -T4 -oA full_scan 192.168.1.100
```

### Évaluation des vulnérabilités

```bash
# Détection de services plus scripts de vulnérabilités
sudo nmap -sV --script=vuln -oA vuln_scan 192.168.1.100
```

### Reconnaissance furtive (empreinte minimale)

```bash
# Scan à profil bas pour les environnements avec surveillance active
sudo nmap -sS -T2 -f --data-length 24 -D RND:5 -oA stealth_scan 192.168.1.100
```
