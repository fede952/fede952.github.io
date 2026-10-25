---
title: "Conta Parole e Convertitore Maiuscole"
description: "Conta parole, caratteri, righe e tempo di lettura in tempo reale; converti maiuscole, rimuovi righe duplicate, pulisci gli spazi o passa al leetspeak."
intro: "**StringMaster** è un piccolo banco di lavoro per il testo. Incolla qualsiasi cosa e conta parole, caratteri, righe e tempo di lettura mentre scrivi; con un clic converte maiuscole e minuscole, rimuove le righe duplicate, ripulisce gli spazi o trasforma il testo in leetspeak. Il testo resta nella scheda del browser."
date: 2026-02-10
lastmod: 2026-10-24
reviewed: false
keywords: ["conta parole", "conta caratteri", "strumenti testo online", "convertitore maiuscole minuscole", "rimuovere righe duplicate", "eliminare spazi online", "convertitore leetspeak", "tempo di lettura"]
tags: ["testo", "strumenti-sviluppo", "scrittura", "strumento"]
app_category: "UtilitiesApplication"
tool_file: "/tools/string-master/"
tool_title: "StringMaster, strumenti di testo"
tool_height: 750
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Incolla o scrivi il testo nella casella **Input**. **Parole**, **Caratteri**, **Righe** e **Tempo di Lettura** si aggiornano a ogni tasto."
  - "Clicca **Maiuscolo** o **Minuscolo** per convertire tutto il testo."
  - "Clicca **Rimuovi Duplicati** per tenere solo la prima occorrenza di ogni riga, oppure **Taglia Spazi** per togliere gli spazi a inizio e fine riga e comprimere le righe vuote."
  - "Clicca **Modalità Hacker** per riscrivere il testo in leetspeak (`hello` → `h3110`)."
  - "Clicca **Copia** per mettere il risultato negli appunti. Le trasformazioni sostituiscono il testo, quindi copia prima l'originale se potrebbe servirti."
faq:
  - q: "Come vengono contate le parole?"
    a: "Il testo viene diviso su qualsiasi sequenza di spazi bianchi (spazi, tabulazioni, a capo): `all'ingrosso` è una parola, `ad es. questo` sono tre. Le lingue scritte senza spazi, come cinese o giapponese, risultano una parola per blocco, quindi per quelle usa il conteggio dei caratteri."
  - q: "Emoji e lettere accentate contano come un carattere?"
    a: "Sì. Il contatore usa il segmentatore di grafemi del browser (`Intl.Segmenter`), quindi 👍, è e perfino un'emoji \"famiglia\" composta da più code point contano una volta sola, come li vedi. Alcune piattaforme, come gli SMS, contano diversamente (in unità UTF-16 o byte) e raggiungono il limite prima."
  - q: "Come viene stimato il tempo di lettura?"
    a: "Numero di parole diviso 200 parole al minuto, una media comune per la lettura a schermo, arrotondato per eccesso. Sotto il minuto mostra i secondi (`45s`), sopra i minuti interi (`4m`). Un testo tecnico o denso si legge di solito più lentamente."
  - q: "Rimuovi Duplicati distingue maiuscole e minuscole?"
    a: "Sì, ed è esatto: `Mela`, `mela` e `mela ` (con uno spazio finale) sono tre righe diverse. Usa prima **Taglia Spazi** e **Minuscolo** per un confronto più permissivo. L'ordine delle prime occorrenze resta invariato, e anche le righe vuote ripetute si riducono a una."
  - q: "Posso annullare una trasformazione?"
    a: "Non c'è un pulsante Annulla e, poiché il testo viene sostituito via script, Ctrl+Z non sempre lo recupera. Minuscolo, Rimuovi Duplicati, Taglia Spazi e Modalità Hacker perdono informazioni: tieni una copia dell'originale."
  - q: "Il leetspeak si può riconvertire?"
    a: "Non in modo affidabile. Sia `i` sia `l` diventano `1`, e le cifre già presenti nel testo non si distinguono da quelle sostituite. La Modalità Hacker è un effetto stilistico a senso unico, non una codifica."
  - q: "Il mio testo viene inviato da qualche parte?"
    a: "No. Conteggi e trasformazioni sono semplice JavaScript nella pagina; nulla viene salvato o trasmesso. Puoi usarlo tranquillamente per bozze, log o documenti interni."
---

## Come funziona

A ogni tasto premuto nella casella viene eseguita la stessa piccola analisi:

- **Parole** = numero di blocchi non vuoti dopo aver diviso il testo (senza spazi agli estremi) sugli spazi bianchi (`/\s+/`).
- **Caratteri** = numero di cluster di grafemi, cioè i caratteri che conterebbe una persona, tramite `Intl.Segmenter`; i browser che non lo supportano contano i code point Unicode. Spazi e a capo contano come caratteri.
- **Righe** = numero di righe separate da a capo. Una casella vuota mostra 0, e un a capo finale aggiunge un'ultima riga vuota.
- **Tempo di Lettura** = ⌈parole ÷ 200 × 60⌉ secondi, mostrato in secondi sotto il minuto e in minuti arrotondati per eccesso oltre.

Ogni pulsante applica una trasformazione all'intero testo e poi ricalcola:

| Pulsante | Cosa fa | Esempio |
|---|---|---|
| **Maiuscolo** | Maiuscolo Unicode (`toUpperCase`) | `straße` → `STRASSE` |
| **Minuscolo** | Minuscolo Unicode (`toLowerCase`) | `CiAO` → `ciao` |
| **Rimuovi Duplicati** | Tiene la prima copia di ogni riga identica, in ordine | `a, b, a, c` → `a, b, c` |
| **Taglia Spazi** | Rifila ogni riga, ammette al massimo una riga vuota di fila, rifila gli estremi | `··testo··` → `testo` |
| **Modalità Hacker** | Sostituisce a→4, b→8, e→3, g→9, i→1, l→1, o→0, s→5, t→7 | `get root` → `937 r007` |
| **Copia** | Copia il testo con la Clipboard API | — |

Due dettagli utili. La conversione delle maiuscole non dipende dalla lingua, quindi la *i* turca con e senza punto segue le regole Unicode generiche. Taglia Spazi interviene solo su estremi di riga e righe vuote: i doppi spazi *dentro* una riga restano, così indentazione del codice e tabelle rimangono leggibili.

## Casi d'uso

- **Scrivere entro un limite.** Controlla tesine, meta description, abstract o post social rispetto a un budget di parole o caratteri mentre li modifichi.
- **Ripulire elenchi.** Incolla una colonna di email, hostname o ID esportata da un foglio di calcolo e rimuovi i duplicati con un clic; passa prima a minuscolo per dati come gli indirizzi email.
- **Sistemare log e output incollati.** Togli gli spazi finali e comprimi le righe vuote dell'output del terminale prima di incollarlo in un ticket o in un documento.
- **Normalizzare identificatori.** Metti in minuscolo tag o chiavi prima di confrontarli, o in maiuscolo costanti e parole chiave SQL.
- **Testo per gioco.** Trasforma un nickname, un banner o il nome di una squadra CTF in leetspeak.
- **Stimare la durata di un intervento.** Il tempo di lettura è un riferimento approssimativo per i copioni; parlando si va più piano, di solito 130–150 parole al minuto.

Per codificare il testo invece di rimodellarlo, vedi il [convertitore Base64](/it/tools/base64-converter/) o il [generatore di hash](/it/tools/hash-generator/).
