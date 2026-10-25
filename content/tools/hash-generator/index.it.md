---
title: "Generatore di Hash: MD5, SHA-256, SHA-512"
description: "Genera hash MD5, SHA-1, SHA-256 e SHA-512 di qualsiasi testo mentre scrivi, con supporto UTF-8 e copia con un clic. Calcolati nel browser, senza upload."
intro: "Scrivi o incolla un testo e ottieni subito i suoi hash **MD5, SHA-1, SHA-256 e SHA-512**, aggiornati mentre digiti. La famiglia SHA viene calcolata dalla Web Crypto API del browser; nulla di ciò che inserisci viene inviato."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["generatore hash", "calcolare sha256", "generatore md5", "hash sha512 online", "hash sha1", "testo in sha256", "calcolo checksum", "calcolatore hash online"]
tags: ["crittografia", "hash", "strumenti-sviluppo", "strumento"]
app_category: "DeveloperApplication"
tool_partial: "hash-generator"
howto:
  - "Scrivi o incolla il testo in **Testo di input**. I quattro hash vengono ricalcolati a ogni tasto premuto."
  - "Leggi il risultato che ti serve: **MD5** (32 caratteri esadecimali), **SHA-1** (40), **SHA-256** (64) o **SHA-512** (128)."
  - "Premi **Copia** accanto a un hash per metterlo negli appunti."
  - "Per confrontarlo con un hash che ti è stato fornito, incollali entrambi in un editor o confrontali carattere per carattere: un solo carattere diverso significa input diverso."
  - "Premi **Cancella tutto** per svuotare input e risultati."
faq:
  - q: "Quale algoritmo di hash devo usare?"
    a: "Per controlli di integrità, impronte e progetti nuovi usa SHA-256 (o SHA-512). MD5 e SHA-1 sono rotti dal punto di vista della sicurezza: esistono attacchi a collisione pratici, quindi non vanno usati per firme o certificati. Vanno ancora bene per usi non di sicurezza, come chiavi di cache o per verificare un checksum di un vecchio sistema."
  - q: "Posso fare l'hash di una password con questo strumento?"
    a: "Puoi calcolare lo SHA-256 di qualsiasi stringa, ma un semplice hash SHA è il modo sbagliato di salvare le password: è progettato per essere veloce, quindi un attaccante può provare miliardi di tentativi al secondo. I sistemi reali usano una funzione di password hashing lenta e con salt, come Argon2id, bcrypt, scrypt o PBKDF2."
  - q: "Perché il mio hash è diverso da quello di un altro strumento?"
    a: "Quasi sempre è diverso l'input. Controlla un a capo finale (`echo` lo aggiunge; usa `echo -n`), gli spazi, i fine riga Windows `\\r\\n` o una codifica del testo diversa. Questo strumento calcola l'hash esattamente dei caratteri nella casella, codificati in UTF-8."
  - q: "Posso fare l'hash di un file?"
    a: "Non con questa pagina: lavora sul testo. Per i file usa la riga di comando: `sha256sum file` su Linux, `shasum -a 256 file` su macOS o `Get-FileHash file -Algorithm SHA256` in PowerShell su Windows."
  - q: "Un hash si può invertire o decifrare?"
    a: "No. Un hash è una funzione a senso unico: non c'è una chiave e non si può risalire all'input dall'output. I siti che \"decifrano MD5\" cercano semplicemente in tabelle di hash precalcolati di parole comuni, ed è proprio per questo che input brevi o comuni non sono protetti dall'hashing."
  - q: "Quello che scrivo viene inviato a un server?"
    a: "No. SHA-1, SHA-256 e SHA-512 sono calcolati con `crypto.subtle.digest()` e MD5 con un'implementazione JavaScript, tutto dentro questa pagina. Non ci sono richieste di rete con il tuo input."
---

## Come funziona

A ogni modifica lo strumento legge la casella di testo, la converte in byte con `TextEncoder` (UTF-8, quindi `é` diventa due byte e un'emoji quattro) ed esegue quattro funzioni di hash in parallelo con `Promise.all`:

- **SHA-1, SHA-256 e SHA-512** passano dalla **Web Crypto API** nativa del browser: `crypto.subtle.digest('SHA-256', bytes)` restituisce un `ArrayBuffer`, poi convertito in esadecimale minuscolo.
- **MD5** non fa parte di Web Crypto, perché è considerato rotto, quindi viene calcolato da una compatta implementazione JavaScript dell'RFC 1321 sugli stessi byte UTF-8.

I risultati sono stringhe esadecimali la cui lunghezza è fissata dall'algoritmo, qualunque sia la dimensione dell'input:

| Algoritmo | Dimensione | Caratteri esadecimali | Stato |
|---|---|---|---|
| MD5 | 128 bit | 32 | Rotto (collisioni dal 2004) |
| SHA-1 | 160 bit | 40 | Rotto (collisione pratica, 2017) |
| SHA-256 | 256 bit | 64 | Sicuro, la scelta più comune |
| SHA-512 | 512 bit | 128 | Sicuro, più veloce su CPU a 64 bit |

Due proprietà rendono utili queste funzioni. Sono **deterministiche**: lo stesso input dà sempre lo stesso hash, su qualsiasi macchina. E hanno un **effetto valanga**: cambia un carattere e circa metà dei bit d'uscita si invertono, quindi `Ciao` e `ciao` hanno SHA-256 completamente diversi. I pulsanti `Copia` usano la Clipboard API, con un'alternativa per i browser più vecchi.

### Testo, non file

L'input è il testo della casella, quindi gli hash coincidono con quelli degli strumenti da riga di comando solo se i byte coincidono esattamente. `printf 'Ciao, Mondo!' | sha256sum` e questo strumento concordano; `echo 'Ciao, Mondo!' | sha256sum` no, perché `echo` aggiunge un a capo.

## Casi d'uso

- **Verificare un checksum.** Molti progetti pubblicano lo SHA-256 di una stringa di release o di una piccola configurazione: incolla il testo e confronta.
- **Debug di firme e API.** Controlla l'hash che un'API si aspetta per un payload, o lo SHA-256 che entra in una firma AWS Signature V4 o nella verifica di un webhook.
- **Chiavi di cache e deduplicazione.** Ricava un identificatore stabile dal testo di un URL, di una query o di un documento.
- **Imparare la crittografia.** Osserva l'effetto valanga in tempo reale, confronta le lunghezze dei digest e capisci perché MD5 e SHA-1 sono in pensione per la sicurezza.
- **Recuperare dati legacy.** Ricrea un valore MD5 o SHA-1 salvato da un vecchio sistema per migrarlo a qualcosa di più robusto.
