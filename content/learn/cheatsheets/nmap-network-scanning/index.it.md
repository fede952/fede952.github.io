---
title: "Manuale Operativo Nmap: Comandi per la Ricognizione di Rete"
description: "Comandi essenziali Nmap per la scansione di rete, rilevamento host, enumerazione porte, rilevamento servizi e valutazione vulnerabilità. Un riferimento tattico rapido per penetration tester."
date: 2026-02-10
tags: ["nmap", "cheatsheet", "penetration-testing", "network-security", "reconnaissance"]
keywords: ["nmap cheatsheet", "comandi nmap", "guida scansione rete", "nmap scansione porte", "nmap rilevamento servizi", "nmap script NSE", "nmap scansione vulnerabilità", "comandi penetration testing"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Manuale Operativo Nmap: Comandi per la Ricognizione di Rete",
    "description": "Comandi essenziali Nmap per la scansione di rete, rilevamento host, enumerazione porte e valutazione vulnerabilità.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "it"
  }
---

## $ System_Init

Nmap è il primo strumento caricato in qualsiasi attività di ricognizione. Mappa la superficie di attacco, identifica gli host attivi, enumera le porte aperte, rileva i servizi e individua le vulnerabilità — tutto da un singolo binario. Questo manuale operativo fornisce i comandi esatti per ogni fase della ricognizione di rete.

Tutti i comandi presuppongono test autorizzati. Utilizzare responsabilmente.

---

## $ Host_Discovery

Identificare i target attivi sulla rete prima della scansione delle porte.

### Ping sweep (ICMP echo)

```bash
# Scoprire host attivi su una subnet usando ping ICMP
nmap -sn 192.168.1.0/24
```

### Scoperta ARP (solo rete locale)

```bash
# Usare richieste ARP per il rilevamento host sulla LAN locale (metodo più veloce)
nmap -sn -PR 192.168.1.0/24
```

### Scoperta TCP SYN su porte specifiche

```bash
# Scoprire host inviando pacchetti SYN alle porte comuni
nmap -sn -PS22,80,443 10.0.0.0/24
```

### Disabilitare risoluzione DNS (velocizzare le scansioni)

```bash
# Saltare i lookup DNS inversi per risultati più veloci
nmap -sn -n 192.168.1.0/24
```

### Scansione lista (nessun pacchetto inviato)

```bash
# Elencare i target che verrebbero scansionati senza inviare alcun pacchetto
nmap -sL 192.168.1.0/24
```

---

## $ Port_Scanning

Enumerare le porte aperte per mappare la superficie di attacco del target.

### Scansione SYN (scansione stealth — predefinita)

```bash
# Scansione half-open: invia SYN, riceve SYN/ACK, invia RST (non completa mai l'handshake)
sudo nmap -sS 192.168.1.100
```

### Scansione TCP connect (non richiede root)

```bash
# Scansione completa con handshake TCP (più lenta ma funziona senza privilegi elevati)
nmap -sT 192.168.1.100
```

### Scansione UDP

```bash
# Scansionare le porte UDP aperte (più lenta a causa del comportamento del protocollo)
sudo nmap -sU 192.168.1.100
```

### Scansionare porte specifiche

```bash
# Scansionare solo porte specifiche
nmap -p 22,80,443,8080 192.168.1.100

# Scansionare un intervallo di porte
nmap -p 1-1024 192.168.1.100

# Scansionare tutte le 65535 porte
nmap -p- 192.168.1.100
```

### Scansione top ports

```bash
# Scansionare le 100 porte più comunemente aperte
nmap --top-ports 100 192.168.1.100
```

### Scansione veloce (top 100 porte)

```bash
# Scansione rapida con numero ridotto di porte per valutazione veloce
nmap -F 192.168.1.100
```

---

## $ Service_Detection

Identificare quale software è in esecuzione su ogni porta aperta.

### Rilevamento versione

```bash
# Sondare le porte aperte per determinare nome e versione del servizio
nmap -sV 192.168.1.100
```

### Rilevamento versione aggressivo

```bash
# Aumentare l'intensità di rilevamento (1-9, predefinito 7)
nmap -sV --version-intensity 9 192.168.1.100
```

### Fingerprinting OS

```bash
# Rilevare il sistema operativo del target usando analisi dello stack TCP/IP
sudo nmap -O 192.168.1.100
```

### Rilevamento combinato servizio + OS

```bash
# Enumerazione completa dei servizi con fingerprinting OS
sudo nmap -sV -O 192.168.1.100
```

### Scansione aggressiva (OS + versione + script + traceroute)

```bash
# Abilitare tutte le funzionalità di rilevamento in un unico flag
sudo nmap -A 192.168.1.100
```

---

## $ NSE_Scripts

Nmap Scripting Engine — rilevamento automatico di vulnerabilità ed enumerazione.

### Eseguire script predefiniti

```bash
# Eseguire il set predefinito di script sicuri e informativi
nmap -sC 192.168.1.100
```

### Eseguire uno script specifico

```bash
# Eseguire un singolo script NSE per nome
nmap --script=http-title 192.168.1.100
```

### Eseguire categorie di script

```bash
# Eseguire tutti gli script di rilevamento vulnerabilità
nmap --script=vuln 192.168.1.100

# Eseguire tutti gli script di discovery
nmap --script=discovery 192.168.1.100

# Eseguire script di brute-force contro servizi di autenticazione
nmap --script=brute 192.168.1.100
```

### Enumerazione HTTP

```bash
# Enumerare directory e file del web server
nmap --script=http-enum 192.168.1.100

# Rilevare web application firewall
nmap --script=http-waf-detect 192.168.1.100
```

### Enumerazione SMB

```bash
# Enumerare condivisioni SMB e utenti (reti Windows)
nmap --script=smb-enum-shares,smb-enum-users 192.168.1.100
```

### Analisi SSL/TLS

```bash
# Verificare dettagli certificato SSL e suite di cifratura
nmap --script=ssl-cert,ssl-enum-ciphers -p 443 192.168.1.100
```

---

## $ Evasion_Techniques

Bypassare firewall e IDS durante penetration test autorizzati.

### Frammentare pacchetti

```bash
# Dividere i pacchetti di sondaggio in frammenti più piccoli per bypassare filtri pacchetti semplici
sudo nmap -f 192.168.1.100
```

### Scansione decoy

```bash
# Generare IP sorgente falsificati per mascherare lo scanner reale
sudo nmap -D RND:10 192.168.1.100
```

### Falsificare porta sorgente

```bash
# Usare una porta sorgente affidabile per bypassare regole firewall basate su porta
sudo nmap --source-port 53 192.168.1.100
```

### Controllo temporizzazione

```bash
# T0=Paranoid, T1=Sneaky, T2=Polite, T3=Normal, T4=Aggressive, T5=Insane
nmap -T2 192.168.1.100
```

### Scansione idle (scansione zombie)

```bash
# Usare un host "zombie" di terze parti per scansionare senza rivelare il proprio IP
sudo nmap -sI zombie-host.com 192.168.1.100
```

---

## $ Output_Formats

Salvare i risultati della scansione per documentazione e post-processing.

### Output normale

```bash
# Salvare i risultati in formato leggibile dall'uomo
nmap -oN scan_results.txt 192.168.1.100
```

### Output XML (per strumenti)

```bash
# Salvare i risultati in formato XML (elaborabile da Metasploit, ecc.)
nmap -oX scan_results.xml 192.168.1.100
```

### Output grepable

```bash
# Salvare i risultati in formato compatibile con grep per scripting
nmap -oG scan_results.gnmap 192.168.1.100
```

### Tutti i formati contemporaneamente

```bash
# Salvare in formato normale, XML e grepable simultaneamente
nmap -oA full_scan 192.168.1.100
```

---

## $ Mission_Templates

Catene di comandi copia-incolla per scenari di engagement comuni.

### Ricognizione rapida

```bash
# Valutazione iniziale veloce di un target
nmap -sS -sV -F -T4 --open 192.168.1.100
```

### Scansione completa porte con rilevamento servizi

```bash
# Scansione completa di tutte le porte con rilevamento versione
sudo nmap -sS -sV -p- -T4 -oA full_scan 192.168.1.100
```

### Valutazione vulnerabilità

```bash
# Rilevamento servizi più script di vulnerabilità
sudo nmap -sV --script=vuln -oA vuln_scan 192.168.1.100
```

### Ricognizione stealth (impronta minima)

```bash
# Scansione a basso profilo per ambienti con monitoraggio attivo
sudo nmap -sS -T2 -f --data-length 24 -D RND:5 -oA stealth_scan 192.168.1.100
```
