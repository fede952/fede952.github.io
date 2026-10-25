---
title: "Oscurare uno screenshot: copri il testo"
description: "Copri email, nomi, IBAN e altre parti sensibili di uno screenshot. Riquadri pieni fusi nei pixel, metadati rimossi, tutto nel browser."
intro: "Incolla uno screenshot (Ctrl+V), trascina un'immagine o sceglila, poi **trascina per coprire** ciò che è sensibile: indirizzi email, nomi, numeri di conto, volti, URL. Le parti coperte sono **riquadri pieni fusi nei pixel** — niente livelli da togliere — e il PNG o JPEG esportato **non contiene metadati**. Un aiuto facoltativo può **suggerire riquadri** su email, IBAN, numeri di carta e di telefono e indirizzi IP. Non viene caricato nulla."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["oscurare screenshot", "coprire testo in un'immagine", "censurare screenshot", "nascondere dati sensibili screenshot", "sfocare immagine online", "pixelare immagine online", "oscurare dati personali foto", "redazione immagini"]
tags: ["privacy", "immagini", "sicurezza", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/screenshot-redactor/"
tool_title: "Oscuratore di screenshot"
tool_height: 1050
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write; clipboard-read"
howto:
  - "Incolla uno screenshot con **Ctrl+V** (⌘V su Mac), trascina un'immagine nel riquadro o premi **Scegli un'immagine**."
  - "Lascia selezionato **Riquadro pieno** (nero per default; scegli un altro **Colore** se vuoi) e trascina su ogni area da nascondere. Sul telefono trascina con un dito e usa **Sposta** per scorrere un'immagine ingrandita."
  - "Facoltativo: premi **Suggerisci aree** per trovare email, IBAN, numeri di carta, numeri di telefono e indirizzi IP con il riconoscimento del testo sul dispositivo. Togli la spunta ai suggerimenti che vuoi lasciare visibili, poi **Copri** gli altri."
  - "Usa **Annulla** / **Ripeti** (Ctrl+Z / Ctrl+Y) e i pulsanti di zoom per controllare i bordi di ogni riquadro."
  - "Scegli **PNG** (testo nitido) o **JPEG** (foto più leggere) e premi **Scarica l'immagine oscurata**, oppure **Copia immagine** per incollarla direttamente in una chat o un ticket."
faq:
  - q: "La mia immagine viene caricata da qualche parte?"
    a: "No. L'immagine viene decodificata, modificata ed esportata nel browser. Anche il riconoscimento del testo facoltativo avviene sul tuo dispositivo; la prima volta scarica i suoi file (circa 10 MB) da questo sito, mai da terze parti, e l'immagine non viene inviata da nessuna parte."
  - q: "Perché un riquadro pieno è più sicuro della sfocatura o dei pixel?"
    a: "Un riquadro pieno sostituisce i pixel con un solo colore: dell'originale non resta nulla. Sfocatura e pixel conservano una versione ridotta dei pixel originali. Con testi brevi o prevedibili — numeri, cifre di una carta, nomi in un font noto — a volte basta per ricostruirli o indovinarli, per esempio sfocando o pixelando allo stesso modo dei testi candidati e confrontando i risultati. Usali solo per ciò che deve semplicemente risaltare meno."
  - q: "Si può togliere l'oscuramento dal file scaricato?"
    a: "No. L'esportazione è un'immagine nuova disegnata dai pixel modificati: niente livelli, niente originale nascosto, nessuna cronologia di modifica nel file. È la differenza rispetto a coprire il testo con una forma in un documento o in un PDF, dove spesso il testo sotto si può ancora selezionare."
  - q: "Rimuove i dati EXIF e GPS?"
    a: "Sì. Il PNG o JPEG esportato viene codificato da zero dal browser e non contiene metadati: niente modello della fotocamera, niente data, niente posizione GPS. L'orientamento della foto viene prima applicato ai pixel, così l'immagine resta dritta."
  - q: "Cosa trova il suggerimento automatico?"
    a: "Indirizzi email, IBAN (verificati con il loro controllo mod 97), numeri di carta (verificati con l'algoritmo di Luhn), numeri di telefono e indirizzi IPv4 e IPv6. Funziona sul testo a schermo in alfabeto latino. Non riconosce nomi, volti, indirizzi o scrittura a mano: controlla sempre anche tu l'immagine prima di condividerla."
  - q: "Quali formati di immagine posso aprire?"
    a: "Tutti quelli che il browser sa mostrare: PNG, JPEG, WebP, GIF (primo fotogramma) e di solito AVIF e BMP. Le foto HEIC dell'iPhone vanno prima convertite, per esempio con il convertitore HEIC di questo sito."
---

## Come funziona

### Le parti coperte sono pixel, non livelli

L'immagine viene decodificata in un canvas a piena risoluzione, applicando l'orientamento EXIF della foto. Ogni riquadro che disegni viene salvato come rettangolo, e una composizione di immagine più riquadri viene ricostruita dai pixel originali a ogni disegno, annullamento o ripetizione. All'esportazione quella composizione viene codificata in un PNG o JPEG del tutto nuovo. Il file contiene solo i pixel finali: ciò che sta sotto un riquadro non esiste più.

Ecco perché gli oscuramenti fatti nei programmi di testo falliscono così spesso: un rettangolo nero disegnato sopra un testo in un documento o in un PDF è un oggetto separato, e il testo sotto si può ancora selezionare o estrarre. Qui sotto non c'è niente.

### Perché sfocatura e pixel hanno un avviso

La pixelatura sostituisce ogni blocco di pixel con il suo colore medio; la sfocatura spalma ogni pixel sui vicini. Entrambe buttano via informazione, ma non tutta. Con il testo, la forma di ogni lettera influisce ancora sul risultato, e i possibili originali sono spesso pochi: un numero di carta ha solo dieci cifre possibili per posizione, e gli screenshot usano pochi font noti. Si possono scrivere testi candidati nello stesso font, pixelarli o sfocarli allo stesso modo e tenere quello che coincide. Strumenti pubblici e ricerche hanno mostrato che funziona su password e numeri pixelati. Un riquadro pieno non lascia nulla da confrontare: per questo è la modalità predefinita e l'unica consigliata per ciò che è segreto.

### I suggerimenti facoltativi

Il riconoscimento del testo usa Tesseract, un motore OCR open source compilato in WebAssembly e servito da questo sito. Si carica solo quando premi **Suggerisci aree**. Le parole riconosciute vengono confrontate con gli schemi di email, IBAN, numeri di carta, numeri di telefono e indirizzi IP; IBAN e carte devono superare anche il controllo della loro cifra di verifica, il che riduce i falsi allarmi. Ogni corrispondenza diventa un riquadro tratteggiato che puoi accettare o scartare.

## Casi d'uso

- **Segnalazioni di bug e ticket di assistenza** — condividi lo screenshot di un errore senza la tua email, l'ID dell'account o una chiave API.
- **Social e forum** — pubblica una conversazione o una ricevuta con nomi, telefoni e numeri d'ordine coperti.
- **Documentazione e tutorial** — nascondi URL interni, indirizzi IP e dati dei clienti negli screenshot dei pannelli di amministrazione.
- **Note spese** — invia la foto di uno scontrino o di un bonifico con il numero di conto oscurato.
- **Lavoro di sicurezza** — inserisci prove in un report senza far trapelare le credenziali o i dati personali che contengono.
