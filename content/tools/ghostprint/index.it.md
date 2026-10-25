---
title: "Test Impronta del Browser: Sei Unico?"
description: "Scopri l'impronta che il browser consegna a ogni sito (canvas, GPU WebGL, audio, font, schermo, fuso orario) e una stima di unicità. Nessun upload."
intro: "**GhostPrint** legge gli stessi segnali che gli script di tracciamento e antifrode leggono in silenzio sulla maggior parte dei siti, te li mostra uno per uno e stima quanto rendono identificabile il tuo browser. Ogni rilevazione avviene in questa pagina; non viene inviato nulla."
date: 2026-07-06
lastmod: 2026-10-24
reviewed: false
keywords: ["test impronta digitale browser", "browser fingerprinting", "fingerprint browser test", "canvas fingerprint", "webgl fingerprint", "quanto sono tracciabile", "sono unico online", "tracciamento senza cookie"]
tags: ["privacy", "sicurezza", "fingerprinting", "strumento"]
app_category: "SecurityApplication"
tool_file: "/tools/ghostprint/"
tool_title: "GhostPrint, test dell'impronta del browser"
tool_height: 2200
tool_settle_ms: 3000
tool_sandbox: "allow-scripts allow-same-origin allow-downloads allow-modals"
tool_allow: "clipboard-write"
howto:
  - "Apri la pagina: la scansione parte da sola. GhostPrint rileva 12 segnali in circa due secondi e li elenca man mano che li legge; **Re-scan** la ripete."
  - "Leggi il verdetto e il numero principale, per esempio \"1 in 2.1 million\": la stima di quanti browser dovresti esaminare prima di trovarne uno con la stessa impronta."
  - "Scorri le schede dei segnali: ognuna mostra il valore grezzo, i bit di informazione identificativa che aggiunge e una spiegazione di una riga."
  - "Annota il tuo **Fingerprint ID**. Apri questa pagina in una finestra anonima o dopo aver cancellato i cookie: l'ID resta uguale, ed è proprio questo il senso del fingerprinting."
  - "Usa **Download shareable card** o **Copy summary** per confrontare i browser o mostrare a un collega perché cancellare i cookie non basta."
faq:
  - q: "Cos'è il browser fingerprinting?"
    a: "È un modo per riconoscere un browser senza salvarci nulla dentro. Uno script legge decine di piccole proprietà (dimensioni dello schermo, font installati, modello di GPU, il modo in cui la tua macchina disegna un'immagine nascosta) e le combina in un identificatore. Non c'è nessun cookie, quindi l'identificatore sopravvive alla navigazione anonima, alla cancellazione dei cookie e alla maggior parte dei pulsanti \"cancella dati\"."
  - q: "Il punteggio di unicità è una misura?"
    a: "È una stima. A ogni segnale è assegnato un peso fisso in bit, basato su quanta informazione identificativa porta di solito quel tipo di segnale secondo la ricerca pubblicata sul fingerprinting; i pesi vengono sommati, scontati del 18% perché i segnali sono correlati, e il risultato è limitato a circa 5,5 miliardi, il numero di utenti di internet. GhostPrint non ti confronta con un database di altri visitatori: è per questo che può funzionare senza raccogliere nulla."
  - q: "La modalità anonima o privata blocca il fingerprinting?"
    a: "No. La modalità privata cancella cookie e cronologia quando la chiudi, ma GPU, font, schermo e rendering del canvas restano gli stessi, quindi anche l'impronta. Puoi verificarlo: il Fingerprint ID mostrato qui non cambia in una finestra anonima."
  - q: "Quali browser resistono meglio al fingerprinting?"
    a: "Tor Browser fa sembrare uguali tutti i suoi utenti, l'approccio più efficace. Brave rende casuali per ogni sito le letture di canvas, WebGL e audio. Firefox ha `privacy.resistFingerprinting`, che standardizza molti valori. Safari riduce alcuni segnali di default. Chrome ed Edge li espongono quasi tutti, a meno di aggiungere un'estensione."
  - q: "Le estensioni anti-fingerprinting servono?"
    a: "Alcune sì, soprattutto quelle che rendono casuali canvas e audio, ma un'estensione rara può diventare a sua volta un tratto distintivo. Anche bloccare del tutto un segnale, come WebGL, può renderti più insolito. L'obiettivo è sembrare comune, non invisibile."
  - q: "Qualche mio dato viene inviato al vostro server?"
    a: "No. Tutte le rilevazioni girano in JavaScript dentro questa pagina e il risultato viene mostrato in locale. Lo strumento non fa richieste a servizi di analytics o di fingerprinting, e la scheda scaricabile viene generata su un canvas nel tuo browser."
---

## Come funziona

GhostPrint raccoglie dodici segnali. Cinque vengono *misurati* attivamente disegnando o elaborando qualcosa; gli altri vengono letti da API standard del browser.

**Segnali di rendering**

- **Canvas.** La pagina disegna un testo (con un'emoji e lettere accentate), un rettangolo pieno e un arco su un canvas nascosto di 240 × 60, lo esporta con `toDataURL()` e calcola l'hash del risultato con FNV-1a a 32 bit. Font, antialiasing, GPU e driver grafico lasciano minuscole differenze nei pixel, quindi l'hash cambia da una macchina all'altra. Un risultato vuoto o minimo viene considerato bloccato.
- **WebGL.** Apre un contesto WebGL, legge produttore e renderer della GPU non mascherati tramite `WEBGL_debug_renderer_info` e li combina in un hash con la versione WebGL, la versione del linguaggio di shading, le dimensioni massime di texture e renderbuffer, il limite di attributi dei vertici e l'elenco completo delle estensioni supportate.
- **Audio.** Un `OfflineAudioContext` elabora un secondo di onda triangolare a 10 kHz attraverso un compressore dinamico. La somma di 1.000 campioni in uscita viene trasformata in hash; le differenze in virgola mobile tra uno stack audio e l'altro la fanno variare da dispositivo a dispositivo. Dopo 900 ms la rilevazione si arrende.
- **Font.** Una stringa di prova nascosta da 72 px viene misurata nelle tre famiglie generiche (serif, sans-serif, monospace) e poi di nuovo con ciascuno di **53 font comuni** messo davanti. Se larghezza o altezza cambiano, il font è installato. L'insieme dei font riflette sistema operativo, lingua e software installati.

**Segnali letti direttamente:** stringa user-agent, piattaforma, risoluzione dello schermo con rapporto pixel e profondità di colore, fuso orario con scostamento UTC, lingue preferite, core della CPU, memoria del dispositivo e punti di tocco, preferenze di schema colori e movimento ridotto, e stato di cookie, Do-Not-Track e Global Privacy Control.

### Dai segnali a "1 in N"

Ogni segnale ha un peso fisso in bit:

| Segnale | Bit |
|---|---|
| Impronta canvas | 8 |
| Font | 0,45 per font rilevato, max 8 |
| Modello di GPU (WebGL) | 7 |
| User agent | 6 (8 se insolitamente lungo) |
| Impronta audio | 5 |
| Schermo, fuso orario | 2 ciascuno |
| Lingue, hardware | 1,5 ciascuno |
| Piattaforma | 1 |
| Preferenze di visualizzazione, flag privacy | 0,5 ciascuno |

Un segnale bloccato o reso casuale vale 0 bit. Il totale viene moltiplicato per **0,82** per tenere conto della correlazione (una certa GPU di solito implica una certa piattaforma, per esempio), poi convertito in "1 su 2^bit", con un tetto di 5,5 miliardi. I verdetti sono *Blending in* sotto i 10 bit, *Identifiable* da 10, *Highly unique* da 18 e *Ghost-level exposure* da 28.

Il **Fingerprint ID** è composto da tre hash FNV-1a di 4 caratteri: di user agent, piattaforma e schermo; degli hash WebGL e canvas; e di tutti i segnali insieme. Il fatto che resti stabile nelle finestre anonime è la dimostrazione pratica.

## Casi d'uso

- **Capire perché "cancella i cookie" non è privacy.** Esegui il test, cancella tutto, eseguilo di nuovo: stesso ID.
- **Confrontare browser e impostazioni.** Prova Firefox con `resistFingerprinting`, Brave, Tor Browser e il tuo browser di tutti i giorni, e guarda quali schede scendono a 0 bit.
- **Formazione sulla sicurezza.** Una demo di 30 secondi delle schede GPU e font rende il concetto concreto anche per i colleghi non tecnici.
- **Verificare le ipotesi antifrode.** Chi sviluppa sistemi di valutazione del rischio vede quali segnali sono stabili e quali si bloccano facilmente.
- **Condividere il risultato.** La scheda scaricabile da 1200 × 630 (formato anteprima social) mostra verdetto, entropia e ID senza esporre i valori grezzi.
