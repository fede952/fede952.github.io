---
title: "Da JPG a PDF: convertire immagini gratis"
description: "Unisci immagini JPG, PNG e WebP in un unico PDF nel browser: riordina, ruota, scegli A4, Letter o il formato dell'immagine e i margini. Senza upload."
intro: "Trasforma foto, scansioni e screenshot in un unico **PDF**: trascina immagini **JPG, PNG, WebP o GIF**, mettile in ordine, ruota quelle storte, scegli **A4, US Letter o il formato dell'immagine** e un margine, e scarica. Le immagini vengono elaborate in questa scheda e i loro dati EXIF e GPS non finiscono mai nel PDF."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["da jpg a pdf", "convertire jpg in pdf", "immagini in pdf", "png in pdf", "foto in pdf", "unire immagini in pdf", "jpg in pdf senza caricare", "webp in pdf"]
tags: ["pdf", "immagini", "privacy", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/images-to-pdf/"
tool_title: "Convertitore da immagini a PDF"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Trascina le immagini nel riquadro oppure fai clic per sceglierle. Ogni immagine diventa una pagina; puoi aggiungerne altre in qualsiasi momento."
  - "Metti le pagine in ordine trascinando le miniature o con **←** e **→**. **⟳** ruota un'immagine di 90°, **✕** la rimuove."
  - "Scegli il **Formato pagina**: **A4**, **US Letter** oppure **Come l'immagine** per pagine che corrispondono esattamente a ogni foto."
  - "Con A4 o Letter, l'orientamento **Automatico (per immagine)** mette le immagini larghe su pagine orizzontali e quelle alte su pagine verticali; puoi forzare **Verticale** o **Orizzontale**. Scegli un **Margine** (nessuno, 1 cm o 2 cm)."
  - "Imposta il **Nome del file** e premi **Crea il PDF e scarica**."
faq:
  - q: "Le mie immagini vengono caricate?"
    a: "No. Le immagini vengono decodificate dal browser, disegnate su un canvas e inserite in un PDF da pdf-lib, tutto dentro questa scheda. Nulla viene inviato a un server, e questo conta per documenti d'identità, ricevute e referti."
  - q: "Il PDF mantiene la posizione o i dati della fotocamera delle mie foto?"
    a: "No. Ogni immagine viene ridisegnata su un canvas prima di essere inserita, e un canvas non porta metadati: i campi EXIF come posizione GPS, data e modello della fotocamera non sono nel PDF. Il PDF riceve solo metadati tecnici di base dalla libreria."
  - q: "Perché le foto del telefono sono nel verso giusto?"
    a: "Spesso i telefoni salvano le foto di lato e registrano la rotazione corretta in un tag EXIF. Lo strumento legge l'immagine con quell'orientamento già applicato prima di disegnarla, così la pagina appare come la foto nella galleria. Usa ⟳ se una scansione è ancora ruotata."
  - q: "Le immagini perdono qualità?"
    a: "Le foto vengono ricodificate in JPEG ad alta qualità (92%), visivamente identico per stampe e documenti. Le immagini PNG, WebP e GIF vengono salvate senza perdita in PNG, mantenendo testi nitidi e aree trasparenti."
  - q: "Quanto sarà grande il PDF?"
    a: "Più o meno quanto le immagini che aggiungi. Foto molto grandi producono PDF grandi; se il file deve restare piccolo per un modulo online, comprimi prima le foto, ad esempio con un compressore di immagini, e poi converti."
  - q: "Posso convertire le foto HEIC dell'iPhone?"
    a: "La maggior parte dei browser non legge direttamente gli HEIC. Convertili prima in JPG con il convertitore HEIC di questo sito — anche lui offline nel browser — e poi aggiungi qui i JPG."
  - q: "Cosa significa \"Come l'immagine\"?"
    a: "La pagina ha le dimensioni della foto a 96 pixel per pollice, più il margine. È la scelta migliore per screenshot e disegni che non devono essere adattati a un formato carta."
---

## Come funziona

### Dall'immagine alla pagina

Per ogni immagine lo strumento:

1. La decodifica con `createImageBitmap(file, { imageOrientation: 'from-image' })`, così l'orientamento EXIF delle foto del telefono viene rispettato.
2. La disegna su un `<canvas>` applicando la tua rotazione e la ricodifica: in **JPEG al 92% di qualità** per le foto JPG, oppure in **PNG** per sorgenti PNG, WebP e GIF, così trasparenze e contorni netti restano intatti. Dei GIF viene usato il primo fotogramma.
3. Inserisce il risultato nel PDF con **pdf-lib** (`embedJpg` / `embedPng`).

### Impaginazione

L'A4 misura 595 × 842 punti e lo US Letter 612 × 792 punti (1 punto = 1/72 di pollice). L'immagine viene ridimensionata per stare nella pagina meno il margine su ogni lato, mantenendo le proporzioni, e centrata. Con l'orientamento automatico la pagina diventa orizzontale quando l'immagine è più larga che alta. Con **Come l'immagine**, la pagina ha la dimensione dell'immagine a 96 DPI — uno screenshot 1920 × 1080 dà una pagina di 1440 × 810 punti — più il margine.

### Librerie

pdf-lib (MIT) viene caricata da questo sito solo quando crei il PDF; la griglia delle miniature usa la decodifica di immagini del browser. Nulla viene richiesto a server di terze parti.

## Casi d'uso

- **Inviare scansioni di documenti cartacei** — ricevute, contratti, compiti — come un unico PDF che qualsiasi ufficio può aprire.
- **Caricare documenti d'identità o buste paga** in un modulo che accetta solo PDF, senza farli passare prima da un convertitore online.
- **Creare un portfolio o un album** di JPG nell'ordine che preferisci.
- **Archiviare screenshot** di una configurazione, di un errore o di una conversazione in un unico file datato.
- **Preparare pagine pronte per la stampa** in A4 o Letter con margini uniformi.
