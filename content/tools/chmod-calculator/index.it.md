---
title: "Calcolatore Chmod: Permessi File Linux"
description: "Attiva lettura, scrittura ed esecuzione per proprietario, gruppo e altri e ottieni il numero chmod (755, 644…), la stringa rwx e il comando da copiare."
intro: "Clicca gli interruttori dei permessi e ottieni il numero **chmod**, la stringa `rwxr-xr-x` che vedi in `ls -l` e un comando pronto da eseguire. I preset coprono i casi comuni: 755, 644, 600, 444 e quello da evitare, 777."
date: 2026-02-14
lastmod: 2026-10-24
reviewed: false
keywords: ["calcolatore chmod", "chmod 755", "permessi file linux", "chmod 644", "permessi ottali", "permessi rwx", "permessi unix", "generatore comando chmod"]
tags: ["linux", "sysadmin", "permessi", "strumento"]
app_category: "DeveloperApplication"
tool_partial: "chmod-calculator"
howto:
  - "Per ogni classe (**Proprietario**, **Gruppo**, **Altri**) attiva o disattiva **Lettura**, **Scrittura** ed **Esecuzione**. Il valore predefinito è 755."
  - "Leggi il numero ottale dopo `chmod` e la stringa simbolica sotto, la stessa notazione che stampa `ls -l`."
  - "Scrivi il nome del file di destinazione: i nomi con spazi o caratteri speciali della shell vengono messi tra apici in automatico nel comando copiato."
  - "Oppure parti da un **preset**: 755 per script e cartelle, 644 per file normali, 600 per chiavi private, 444 per file in sola lettura."
  - "Premi **Copia comando** e incollalo nel terminale."
faq:
  - q: "Cosa significa chmod 755?"
    a: "7 per il proprietario (lettura 4 + scrittura 2 + esecuzione 1), 5 per il gruppo (lettura 4 + esecuzione 1) e 5 per gli altri. Il proprietario può fare tutto; gli altri possono leggere ed eseguire ma non modificare. È lo standard per script, eseguibili e cartelle."
  - q: "Che differenza c'è tra 644 e 755?"
    a: "644 (`rw-r--r--`) non ha il bit di esecuzione: va bene per documenti, configurazioni e file web. 755 (`rwxr-xr-x`) aggiunge l'esecuzione per tutti: serve per script e programmi, e per le cartelle, dove \"esecuzione\" significa poterci entrare."
  - q: "Perché chmod 777 è pericoloso?"
    a: "Permette a qualsiasi utente del sistema di modificare il file o la cartella. Su un server condiviso o nella document root di un sito, qualsiasi processo compromesso può sostituire il tuo codice o depositare file. Se qualcosa funziona solo con 777, la vera soluzione di solito è il proprietario o il gruppo del file (`chown`), non permessi più larghi."
  - q: "Che permessi deve avere una chiave privata SSH?"
    a: "600 (`rw-------`): leggibile e scrivibile solo da te. OpenSSH rifiuta una chiave privata leggibile da altri e mostra \"UNPROTECTED PRIVATE KEY FILE\". La cartella `~/.ssh` dovrebbe essere 700."
  - q: "Cosa significa esecuzione su una cartella?"
    a: "È il permesso di attraversarla: entrarci con `cd` e accedere ai file al suo interno per nome. La lettura su una cartella permette di elencarne i nomi; senza esecuzione vedi i nomi ma non puoi aprire i file. Per questo le cartelle sono di solito 755 o 700."
  - q: "Supporta setuid, setgid o lo sticky bit?"
    a: "No. Il calcolatore copre i nove bit di base, il modo a tre cifre usato in quasi tutti i comandi `chmod`. I bit speciali sono una quarta cifra iniziale (4 setuid, 2 setgid, 1 sticky, come in `chmod 1777 /tmp`): aggiungila a mano se ti serve."
---

## Come funziona

I permessi Unix sono nove bit in tre gruppi da tre. Ogni gruppo risponde alle stesse tre domande, lettura, scrittura, esecuzione, per una classe di utenti: il **proprietario** del file (`u`), il suo **gruppo** (`g`) e tutti gli altri (`o`).

Ogni permesso ha un valore fisso e una cifra è semplicemente la loro somma:

| Permesso | Valore | Simbolo |
|---|---|---|
| Lettura | 4 | `r` |
| Scrittura | 2 | `w` |
| Esecuzione | 1 | `x` |

Quindi 7 = 4 + 2 + 1 = `rwx`, 6 = 4 + 2 = `rw-`, 5 = 4 + 1 = `r-x` e 4 = `r--`. Il calcolatore somma gli interruttori attivi per classe, scrive le tre cifre una accanto all'altra e riconverte ogni cifra in `r`, `w`, `x` o `-` con un test sui bit (`cifra & 4`, `& 2`, `& 1`). Il `-` iniziale della stringa simbolica è il carattere del tipo di file che `ls -l` mostra per un file normale (`d` per una cartella).

I preset fanno il contrario: ogni cifra di `644` viene scomposta nei suoi bit per impostare i nove interruttori.

Il comando copiato è `chmod <ottale> <file>`. Se il nome contiene qualcosa di diverso da lettere, cifre e `._/@%+=:,-`, viene racchiuso tra apici singoli (`'mio file.sh'`), con gli apici interni gestiti alla maniera POSIX, così il comando si può incollare senza rischi in bash o zsh.

### Modi comuni

| Modo | Simbolico | Uso tipico |
|---|---|---|
| 755 | `rwxr-xr-x` | Script, eseguibili, cartelle |
| 644 | `rw-r--r--` | File normali, configurazioni, file web |
| 700 | `rwx------` | Cartelle private come `~/.ssh` |
| 600 | `rw-------` | Chiavi private, file `.env`, credenziali |
| 444 | `r--r--r--` | File che nessuno deve modificare |
| 777 | `rwxrwxrwx` | Quasi mai: chiunque può modificarlo |

## Casi d'uso

- **"Permission denied" eseguendo uno script.** Aggiungi il bit di esecuzione: `chmod 755 deploy.sh`, oppure `chmod u+x` se lo esegui solo tu.
- **Proteggere i segreti.** Porta a 600 file `.env`, file con API key e chiavi SSH, così gli altri utenti della macchina non possono leggerli.
- **Web server.** Le configurazioni tipiche usano 644 per i file e 755 per le cartelle, di proprietà dell'utente di deploy e leggibili dal web server.
- **Docker e CI.** I file copiati nelle immagini o scaricati dalla CI a volte perdono il bit di esecuzione: il calcolatore ti dà la riga `RUN chmod` esatta.
- **Imparare la notazione.** Passa dall'output di `ls -l` ai numeri ottali finché leggere `drwxr-x---` diventa automatico.
