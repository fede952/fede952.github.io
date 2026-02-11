---
title: "Colloquio Linux SysAdmin: Processi, Permessi e Networking"
description: "20 domande essenziali per colloqui di amministrazione di sistemi Linux per ruoli Senior SysAdmin e DevOps. Copre permessi dei file, gestione dei processi, systemd, networking e troubleshooting."
date: 2026-02-11
tags: ["linux", "interview", "sysadmin", "devops"]
keywords: ["linux interview questions", "red hat interview", "bash scripting questions", "linux permissions interview", "sysadmin interview questions", "linux process management", "systemd interview", "linux networking questions", "senior linux engineer", "rhcsa exam prep"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Colloquio Linux SysAdmin: Processi, Permessi e Networking",
    "description": "20 domande essenziali per colloqui di amministrazione di sistemi Linux su permessi, processi, systemd e networking.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "it"
  }
---

## Inizializzazione del Sistema

L'amministrazione di sistemi Linux è la base dell'infrastruttura moderna. Che tu stia sostenendo un colloquio per un ruolo da SysAdmin, DevOps, SRE o Cloud Engineer, verrai testato sulla tua capacità di gestire utenti, risolvere problemi dei processi, configurare il networking e mettere in sicurezza i server — tutto dalla riga di comando. Questa guida copre 20 domande che separano i candidati senior da quelli junior, con risposte che dimostrano una reale esperienza operativa.

**Hai bisogno di un riferimento rapido ai comandi?** Tieni aperto il nostro [Cheatsheet Linux SysAdmin](/cheatsheets/linux-sysadmin-permissions/) durante la preparazione.

---

## Permessi e Proprietà dei File

<details>
<summary><strong>1. Spiega il modello dei permessi di Linux (rwx, notazione ottale, bit speciali).</strong></summary>
<br>

Ogni file ha tre livelli di permessi: **Proprietario**, **Gruppo**, **Altri**. Ogni livello può avere **Lettura (r=4)**, **Scrittura (w=2)**, **Esecuzione (x=1)**.

La notazione ottale combina questi valori: `chmod 755` = rwxr-xr-x (proprietario: tutti i permessi, gruppo/altri: lettura+esecuzione).

**Bit speciali**:
- **SUID (4000)**: Il file viene eseguito come il proprietario del file, non come l'utente che lo esegue. Esempio: `/usr/bin/passwd` viene eseguito come root in modo che gli utenti possano cambiare la propria password.
- **SGID (2000)**: Sui file, viene eseguito come il gruppo proprietario. Sulle directory, i nuovi file ereditano il gruppo della directory.
- **Sticky bit (1000)**: Sulle directory, solo il proprietario del file può cancellare i propri file. Esempio classico: `/tmp`.
</details>

<details>
<summary><strong>2. Qual è la differenza tra hard link e soft link?</strong></summary>
<br>

- **Hard link**: Un riferimento diretto all'inode (i dati effettivi sul disco). Più hard link allo stesso file condividono lo stesso numero di inode. L'eliminazione di un hard link non influisce sugli altri — i dati persistono finché tutti gli hard link non vengono rimossi. Non può attraversare i confini del filesystem. Non può collegarsi alle directory.
- **Soft link (symlink)**: Un puntatore a un percorso file (come una scorciatoia). Ha il proprio inode. Se il file di destinazione viene eliminato, il symlink diventa un collegamento pendente. Può attraversare i filesystem. Può collegarsi alle directory.

Usa `ls -li` per vedere i numeri degli inode e confermare le relazioni tra hard link.
</details>

<details>
<summary><strong>3. Uno sviluppatore non riesce a scrivere in una directory condivisa. Come diagnostichi e risolvi il problema?</strong></summary>
<br>

Passaggi diagnostici:
1. `ls -la /shared/` — controlla proprietà e permessi.
2. `id developer` — controlla a quali gruppi appartiene l'utente.
3. `getfacl /shared/` — controlla le ACL che potrebbero sovrascrivere i permessi standard.

Soluzioni comuni:
- Aggiungi l'utente al gruppo della directory: `sudo usermod -aG devteam developer`.
- Imposta SGID sulla directory in modo che i nuovi file ereditino il gruppo: `chmod g+s /shared/`.
- Se servono le ACL: `setfacl -m u:developer:rwx /shared/`.
- Assicurati che l'umask non stia bloccando la scrittura del gruppo (controlla con il comando `umask`).
</details>

<details>
<summary><strong>4. Cos'è umask e come influisce sulla creazione dei file?</strong></summary>
<br>

`umask` definisce i permessi predefiniti **rimossi** dai nuovi file e directory. È una maschera di bit sottratta dai permessi massimi.

- Massimo predefinito per i file: 666 (nessuna esecuzione per impostazione predefinita).
- Massimo predefinito per le directory: 777.
- Con `umask 022`: i file ottengono 644 (rw-r--r--), le directory ottengono 755 (rwxr-xr-x).
- Con `umask 077`: i file ottengono 600 (rw-------), le directory ottengono 700 (rwx------).

Impostato a livello di sistema in `/etc/profile` o per utente in `~/.bashrc`. Fondamentale per la sicurezza — un umask troppo permissivo può esporre file sensibili a utenti non autorizzati.
</details>

## Gestione dei Processi

<details>
<summary><strong>5. Spiega la differenza tra un processo, un thread e un demone.</strong></summary>
<br>

- **Processo**: Un'istanza di un programma in esecuzione con il proprio spazio di memoria, PID, descrittori di file e ambiente. Creato da `fork()` o `exec()`.
- **Thread**: Un'unità di esecuzione leggera all'interno di un processo. I thread condividono lo stesso spazio di memoria e i descrittori di file ma hanno il proprio stack e registri. Più veloci da creare rispetto ai processi.
- **Demone**: Un processo in background che viene eseguito senza un terminale di controllo. Tipicamente avviato al boot, viene eseguito continuamente e fornisce un servizio (sshd, nginx, cron). Convenzionalmente denominato con il suffisso `d`.
</details>

<details>
<summary><strong>6. Cosa sono i processi zombie e come li gestisci?</strong></summary>
<br>

Uno **zombie** è un processo che ha terminato l'esecuzione ma ha ancora una voce nella tabella dei processi perché il suo genitore non ha chiamato `wait()` per leggere il suo stato di uscita. Non consuma risorse tranne uno slot PID.

Identifica gli zombie: `ps aux | grep Z` — mostrano stato `Z` (defunct).

**Non puoi** uccidere uno zombie — è già morto. Per rimuoverlo:
1. Invia `SIGCHLD` al processo genitore: `kill -s SIGCHLD <parent_pid>`.
2. Se il genitore lo ignora, uccidere il processo genitore renderà orfano lo zombie, che verrà adottato da `init` (PID 1). Init chiama automaticamente `wait()` e lo ripulisce.

Un gran numero di zombie di solito indica un processo genitore difettoso che non sta raccogliendo i suoi figli.
</details>

<details>
<summary><strong>7. Spiega i segnali Linux. Cosa sono SIGTERM, SIGKILL e SIGHUP?</strong></summary>
<br>

I segnali sono interruzioni software inviate ai processi:

- **SIGTERM (15)**: Richiesta di terminazione cortese. Il processo può intercettarlo, ripulire le risorse e uscire in modo ordinato. Questo è ciò che `kill <pid>` invia per impostazione predefinita.
- **SIGKILL (9)**: Terminazione forzata. Non può essere intercettato, bloccato o ignorato. Il kernel termina il processo immediatamente. Usalo solo come ultima risorsa — nessuna pulizia possibile.
- **SIGHUP (1)**: Storicamente "hangup". Molti demoni (nginx, Apache) ricaricano la loro configurazione quando ricevono SIGHUP, invece di riavviarsi.
- **SIGINT (2)**: Interruzione, inviato da Ctrl+C.
- **SIGSTOP/SIGCONT (19/18)**: Pausa e riprendi un processo.
</details>

<details>
<summary><strong>8. Come trovi e termini un processo che consuma troppa CPU?</strong></summary>
<br>

1. Identifica il processo: `top -o %CPU` o `ps aux --sort=-%cpu | head -10`.
2. Ottieni dettagli: `ls -l /proc/<pid>/exe` per vedere il binario effettivo.
3. Controlla cosa sta facendo: `strace -p <pid>` per le chiamate di sistema, `lsof -p <pid>` per i file aperti.
4. Arresto ordinato: `kill <pid>` (SIGTERM) — permetti la pulizia.
5. Arresto forzato: `kill -9 <pid>` (SIGKILL) — solo se SIGTERM fallisce.
6. Prevenire il ripetersi: Se gestito da systemd, imposta `CPUQuota=50%` nel file unit del servizio.
</details>

## Systemd e Servizi

<details>
<summary><strong>9. Cos'è systemd e come si differenzia da SysVinit?</strong></summary>
<br>

**SysVinit**: Processo di avvio sequenziale che utilizza script shell in `/etc/init.d/`. I servizi si avviano uno dopo l'altro in un livello di esecuzione definito. Tempi di avvio lenti. Semplice ma con gestione delle dipendenze limitata.

**systemd**: Processo di avvio parallelo che utilizza file unit. Supporta dipendenze, attivazione via socket, avvio dei servizi on-demand, cgroups per il controllo delle risorse e journald per il logging. Avvio molto più veloce. Gestisce servizi, timer, mount, socket e target.

systemd è il sistema init predefinito su RHEL, Ubuntu, Debian, Fedora, SUSE e Arch.
</details>

<details>
<summary><strong>10. Come crei un servizio systemd personalizzato?</strong></summary>
<br>

Crea un file unit in `/etc/systemd/system/myapp.service`:

```ini
[Unit]
Description=My Application
After=network.target

[Service]
Type=simple
User=deploy
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/bin/server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Poi: `sudo systemctl daemon-reload && sudo systemctl enable --now myapp`.

Valori chiave di `Type`: `simple` (predefinito, il processo principale viene eseguito in primo piano), `forking` (il processo fa fork in background, necessita di `PIDFile`), `oneshot` (viene eseguito una volta e termina), `notify` (il processo segnala la prontezza tramite sd_notify).
</details>

<details>
<summary><strong>11. Come analizzi le prestazioni di avvio con systemd?</strong></summary>
<br>

- `systemd-analyze` — tempo totale di avvio.
- `systemd-analyze blame` — elenco dei servizi ordinati per tempo di avvio.
- `systemd-analyze critical-chain` — albero del percorso critico di avvio.
- `systemd-analyze plot > boot.svg` — genera una timeline visuale della sequenza di avvio.
- `journalctl -b -p err` — errori dall'avvio corrente.

Per velocizzare l'avvio: disabilita i servizi non necessari (`systemctl disable`), converti i servizi all'attivazione via socket (avvio on-demand) e identifica i servizi lenti dall'output blame.
</details>

## Networking

<details>
<summary><strong>12. Spiega il three-way handshake TCP.</strong></summary>
<br>

1. **SYN**: Il client invia un pacchetto SYN al server con un numero di sequenza iniziale.
2. **SYN-ACK**: Il server risponde con SYN-ACK, confermando il SYN del client e inviando il proprio numero di sequenza.
3. **ACK**: Il client invia un ACK confermando il numero di sequenza del server. La connessione è stabilita.

La chiusura utilizza un handshake a quattro vie: FIN → ACK → FIN → ACK (ogni lato chiude indipendentemente la propria metà della connessione).

Debug con: `ss -tuln` (porte in ascolto), `ss -tulnp` (con nomi dei processi), `tcpdump -i eth0 port 80` (cattura dei pacchetti).
</details>

<details>
<summary><strong>13. Qual è la differenza tra TCP e UDP?</strong></summary>
<br>

- **TCP** (Transmission Control Protocol): Orientato alla connessione, affidabile, consegna ordinata. Utilizza handshake, acknowledgment, ritrasmissioni. Overhead maggiore. Usato per HTTP, SSH, FTP, database.
- **UDP** (User Datagram Protocol): Senza connessione, non affidabile, nessun ordine garantito. Nessun handshake, nessun acknowledgment. Overhead minore, latenza inferiore. Usato per DNS, DHCP, VoIP, streaming, gaming.

Concetto chiave: "Non affidabile" non significa scadente — significa che l'applicazione gestisce l'affidabilità se necessario. Il DNS usa UDP perché le query sono piccole e veloci; se una risposta viene persa, il client semplicemente la rinvia.
</details>

<details>
<summary><strong>14. Un server non riesce a raggiungere un IP esterno. Come fai il troubleshooting?</strong></summary>
<br>

Approccio livello per livello:
1. **L1 - Fisico**: `ip link show` — l'interfaccia è attiva?
2. **L2 - Data Link**: `ip neighbor show` — la tabella ARP è popolata?
3. **L3 - Rete**: `ip route show` — c'è un gateway predefinito? `ping <gateway>` — riesci a raggiungerlo?
4. **L3 - Esterno**: `ping 8.8.8.8` — riesci a raggiungere internet tramite IP?
5. **L7 - DNS**: `nslookup google.com` — la risoluzione DNS funziona? Controlla `/etc/resolv.conf`.
6. **Firewall**: `iptables -L -n` o `nft list ruleset` — le connessioni in uscita sono bloccate?
7. **Traccia del percorso**: `traceroute 8.8.8.8` — dove si interrompe il percorso?
</details>

## Storage e Filesystem

<details>
<summary><strong>15. Cos'è un inode?</strong></summary>
<br>

Un inode è una struttura dati che memorizza i metadati di un file: permessi, proprietà, dimensione, timestamp e puntatori ai blocchi dati sul disco. Ogni file e directory ha un inode.

Un aspetto fondamentale è che il **nome del file NON è memorizzato nell'inode** — è memorizzato nella voce della directory, che mappa un nome a un numero di inode. Ecco perché gli hard link funzionano: più voci di directory possono puntare allo stesso inode.

Esaurire gli inode (anche con spazio libero su disco) impedisce la creazione di nuovi file. Controlla con `df -i`. Causa comune: milioni di file minuscoli (code di posta, directory di cache).
</details>

<details>
<summary><strong>16. Come estendi un volume logico LVM senza downtime?</strong></summary>
<br>

1. Controlla lo spazio disponibile: `vgdisplay` — cerca i PE (physical extents) liberi.
2. Se non c'è spazio libero, aggiungi un nuovo disco fisico: `pvcreate /dev/sdb && vgextend myvg /dev/sdb`.
3. Estendi il volume logico: `lvextend -L +10G /dev/myvg/mylv`.
4. Ridimensiona il filesystem (online per ext4/XFS):
   - ext4: `resize2fs /dev/myvg/mylv`
   - XFS: `xfs_growfs /mountpoint`

Nessun umount necessario. Nessun downtime. Questo è uno dei principali vantaggi di LVM rispetto alle partizioni raw.
</details>

## Sicurezza e Hardening

<details>
<summary><strong>17. Qual è la differenza tra su, sudo e sudoers?</strong></summary>
<br>

- **su** (switch user): Cambia interamente ad un altro utente. `su -` carica l'ambiente dell'utente di destinazione. Richiede la password dell'utente di destinazione.
- **sudo** (superuser do): Esegue un singolo comando come un altro utente (di solito root). Richiede la password del **chiamante**. Fornisce logging di audit di chi ha eseguito cosa.
- **sudoers** (`/etc/sudoers`): File di configurazione che definisce chi può usare sudo e quali comandi può eseguire. Modificato in sicurezza con `visudo` (validazione della sintassi).

Best practice: Disabilita il login diretto come root (`PermitRootLogin no` in sshd_config). Dai invece accesso sudo agli amministratori — fornisce responsabilità (registra chi ha fatto cosa) e controllo granulare.
</details>

<details>
<summary><strong>18. Come fai l'hardening di un server SSH?</strong></summary>
<br>

Modifiche essenziali in `/etc/ssh/sshd_config`:
- `PermitRootLogin no` — impedisci il login diretto come root.
- `PasswordAuthentication no` — forza l'autenticazione basata su chiave.
- `PubkeyAuthentication yes` — abilita le chiavi SSH.
- `Port 2222` — cambia dalla porta predefinita (riduce le scansioni automatizzate).
- `MaxAuthTries 3` — limita i tentativi di autenticazione.
- `AllowUsers deploy admin` — whitelist di utenti specifici.
- `ClientAliveInterval 300` — disconnetti le sessioni inattive.
- Installa `fail2ban` — banna automaticamente gli IP dopo tentativi di login falliti.
</details>

## Scripting e Automazione

<details>
<summary><strong>19. Qual è la differenza tra $?, $$, $! e $@ in Bash?</strong></summary>
<br>

- **$?** — Stato di uscita dell'ultimo comando (0 = successo, non-zero = fallimento).
- **$$** — PID della shell corrente.
- **$!** — PID dell'ultimo processo in background.
- **$@** — Tutti gli argomenti passati allo script (ciascuno come una parola separata).
- **$#** — Numero di argomenti.
- **$0** — Nome dello script stesso.
- **$1, $2, ...** — Singoli argomenti posizionali.

Pattern comune: `command && echo "success" || echo "fail"` utilizza `$?` implicitamente.
</details>

<details>
<summary><strong>20. Scrivi un one-liner per trovare tutti i file più grandi di 100MB modificati negli ultimi 7 giorni.</strong></summary>
<br>

```bash
find / -type f -size +100M -mtime -7 -exec ls -lh {} \; 2>/dev/null
```

Spiegazione:
- `find /` — cerca dalla root.
- `-type f` — solo file (non directory).
- `-size +100M` — più grandi di 100 megabyte.
- `-mtime -7` — modificati negli ultimi 7 giorni.
- `-exec ls -lh {} \;` — mostra la dimensione in formato leggibile per ogni risultato.
- `2>/dev/null` — sopprime gli errori di permesso negato.

Alternativa con ordinamento: `find / -type f -size +100M -mtime -7 -printf '%s %p\n' 2>/dev/null | sort -rn | head -20`.
</details>
