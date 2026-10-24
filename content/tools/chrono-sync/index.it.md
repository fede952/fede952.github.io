---
title: "Convertitore Timestamp Unix (Epoch in Data)"
description: "Converti timestamp Unix in date e date in epoch, in UTC e ora locale. Secondi o millisecondi riconosciuti in automatico, con orologio epoch in diretta."
intro: "**ChronoSync** converte i **timestamp Unix (epoch)** in date leggibili e viceversa. Mostra il timestamp attuale che scorre in tempo reale, accetta secondi o millisecondi e dà ogni risultato sia in UTC sia nel tuo fuso orario."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["convertitore timestamp unix", "convertire epoch", "timestamp in data", "data in timestamp", "epoch time adesso", "unix time", "millisecondi in data", "convertitore epoch"]
tags: ["strumenti-sviluppo", "tempo", "convertitore", "strumento"]
app_category: "DeveloperApplication"
tool_file: "/tools/chrono-sync/"
tool_title: "ChronoSync, convertitore di timestamp Unix"
tool_height: 700
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Leggi il **Timestamp UNIX Attuale** in alto: si aggiorna ogni secondo, con lo stesso istante in UTC sotto."
  - "Per trasformare un timestamp in data, incollalo in **Timestamp → Data** e premi **Converti**. I valori a 10 cifre sono letti come secondi, quelli a 13 come millisecondi."
  - "Leggi il risultato: prima la data in UTC, poi lo stesso istante nel fuso orario locale del browser."
  - "Per ottenere un timestamp, scegli data e ora in **Data → Timestamp** (ora locale, al secondo) e premi **Converti**."
  - "Usa il piccolo pulsante di copia accanto a ogni risultato per metterlo negli appunti."
faq:
  - q: "Cos'è un timestamp Unix?"
    a: "Il numero di secondi trascorsi dalle 00:00:00 UTC del 1° gennaio 1970, l'\"epoch\" Unix, senza contare i secondi intercalari. In un dato istante è uguale in tutto il mondo, ed è per questo che server, database e log lo usano: 1700000000 è il 14 novembre 2023 alle 22:13:20 UTC qualunque sia il tuo fuso."
  - q: "Secondi o millisecondi?"
    a: "Gli strumenti Unix, PHP, `time.time()` di Python (come intero) e la maggior parte dei database usano i secondi, oggi 10 cifre. `Date.now()` di JavaScript, `System.currentTimeMillis()` di Java e molte API usano i millisecondi, 13 cifre. ChronoSync tratta come millisecondi gli input da 13 cifre in su e segna il risultato con (ms)."
  - q: "Perché la data convertita sembra sbagliata di una o due ore?"
    a: "Perché un timestamp non ha fuso orario: ce l'ha solo la sua visualizzazione. Confronta la riga UTC, non quella locale, con il server o i log, che di solito sono in UTC. L'ora legale spiega le differenze che compaiono solo in una parte dell'anno."
  - q: "Cos'è il problema dell'anno 2038?"
    a: "I sistemi che salvano i timestamp come interi con segno a 32 bit vanno in overflow a 2147483647, cioè le 03:14:07 UTC del 19 gennaio 2038. Dopo, il valore diventa negativo e le date tornano al 1901. I sistemi moderni usano valori a 64 bit, ma dispositivi embedded e vecchi formati di file sono ancora a rischio."
  - q: "Funziona anche con date prima del 1970?"
    a: "Sì. I timestamp negativi contano i secondi prima dell'epoch: -86400 è il 31 dicembre 1969 alle 00:00 UTC. Inserisci il segno meno e converti come al solito."
  - q: "Come ottengo il timestamp attuale nel codice?"
    a: "Bash: `date +%s`. Python: `int(time.time())`. JavaScript: `Math.floor(Date.now() / 1000)`. PHP: `time()`. SQL (PostgreSQL): `extract(epoch from now())`. PowerShell: `[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()`."
---

## Come funziona

È tutto JavaScript con l'oggetto `Date` del browser, che internamente conserva il tempo come millisecondi dall'epoch.

**Orologio in diretta.** Ogni secondo la pagina calcola `Math.floor(Date.now() / 1000)` e lo mostra accanto al `toISOString()` dello stesso istante, nel formato `AAAA-MM-GG HH:MM:SS UTC`.

**Timestamp → data.** L'input deve essere un intero, eventualmente negativo. Se ha 13 cifre o più viene considerato in millisecondi; altrimenti viene moltiplicato per 1000. La `Date` risultante viene mostrata due volte:

1. in **UTC**, da `toISOString()`, la forma non ambigua da confrontare con log e server;
2. in **ora locale**, da `toLocaleString()`, che usa il fuso orario e il formato di data del browser.

**Data → timestamp.** Il selettore è un `<input type="datetime-local">`, che non ha un fuso proprio: il browser lo interpreta nel fuso locale. `getTime() / 1000`, arrotondato per difetto, dà i secondi epoch. Il selettore parte già impostato sull'ora locale attuale.

| Timestamp | Data UTC | Nota |
|---|---|---|
| `0` | 1970-01-01 00:00:00 | L'epoch |
| `1000000000` | 2001-09-09 01:46:40 | Primo timestamp a 10 cifre |
| `1700000000` | 2023-11-14 22:13:20 | |
| `2000000000` | 2033-05-18 03:33:20 | |
| `2147483647` | 2038-01-19 03:14:07 | Massimo valore con segno a 32 bit |
| `-86400` | 1969-12-31 00:00:00 | Un giorno prima dell'epoch |

I secondi intercalari non fanno parte del tempo Unix, quindi un timestamp corrisponde a un solo istante UTC (a parte il raro secondo intercalare stesso) e due timestamp differiscono esattamente del loro numero di secondi.

## Casi d'uso

- **Leggere log e JWT.** Trasforma `exp`, `iat` e campi di log come `1729771200` in una data su cui ragionare.
- **Debug dei fusi orari.** Vedi al volo se un valore salvato è la mezzanotte UTC o quella locale.
- **Scrivere query.** Ottieni il timestamp di "1 marzo 2026 00:00" da incollare in una clausola SQL `WHERE` o in un filtro di un'API.
- **Passare da un linguaggio all'altro.** Verifica se un valore da JavaScript (ms) e uno da Python (s) indicano lo stesso momento.
- **Cron e pianificazione.** Controlla quando partirà davvero un job pianificato in tempo epoch.
