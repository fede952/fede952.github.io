---
title: "Convertire HEIC in JPG senza upload"
description: "Converti le foto HEIC dell'iPhone in JPG o PNG nel browser: in blocco, con qualità regolabile, rimozione EXIF/GPS opzionale e download ZIP. Nessun upload."
intro: "Trasforma le **foto HEIC dell'iPhone in JPG o PNG** senza caricarle da nessuna parte: trascina uno o cento file, scegli formato e qualità, decidi se rimuovere i metadati EXIF e la posizione GPS e scarica ogni file o un unico ZIP. Il decoder gira dentro questa scheda del browser."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["convertire heic in jpg", "heic to jpg", "convertitore heic", "heic in png", "foto iphone in jpg", "aprire file heic", "convertire heic online", "heic jpg gratis"]
tags: ["immagini", "privacy", "convertitore", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/heic-converter/"
tool_title: "Convertitore da HEIC a JPG e PNG"
tool_height: 720
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Trascina le foto `.heic` o `.heif` nel riquadro oppure fai clic per sceglierle. Puoi aggiungerne più di una alla volta, e altre in seguito."
  - "La prima volta la pagina carica il decoder HEIC (circa 1,5 MB, una volta per visita). Poi ogni foto viene decodificata e convertita: accanto al nome compaiono una miniatura e la nuova dimensione."
  - "Scegli **JPG** (file più leggeri, **Qualità JPG** regolabile) o **PNG** (senza perdita, più pesante). Cambiando un'opzione le foto già in elenco vengono riconvertite."
  - "Lascia attivo **Rimuovi i metadati (EXIF, posizione GPS)** per ottenere file puliti, oppure disattivalo per mantenere nel JPG i dati della fotocamera e la posizione."
  - "Premi **Scarica** su una foto, oppure **Scarica tutto (.zip)** per salvare tutti i file convertiti in un unico archivio."
faq:
  - q: "Le mie foto vengono caricate su un server?"
    a: "No. I file vengono letti con la File API del browser e decodificati da una versione WebAssembly di libheif che gira in questa scheda. Le uniche richieste di rete servono a scaricare il decoder; le foto non lasciano mai il dispositivo. Puoi verificarlo nel pannello Rete del browser durante la conversione."
  - q: "Perché l'iPhone salva le foto in HEIC?"
    a: "HEIC contiene un'immagine compressa con HEVC (H.265) dentro un contenitore HEIF. A parità di qualità i file pesano circa la metà di un JPEG, per questo iOS lo usa di default. Molte app Windows, siti web e dispositivi meno recenti però non lo aprono: da qui la necessità di convertire."
  - q: "Perderò qualità?"
    a: "La conversione in JPEG ricomprime l'immagine. Con la qualità predefinita di 85 la differenza è difficilissima da vedere e il file resta leggero; imposta 95–100 se vuoi ritoccare la foto. Il PNG è senza perdita ma spesso pesa da tre a cinque volte l'HEIC originale."
  - q: "Cosa rimuove \"Rimuovi i metadati\"?"
    a: "Tutto tranne i pixel: i dati EXIF della fotocamera, data e ora e soprattutto la posizione GPS, che può rivelare dove abiti o lavori. Con l'opzione disattivata il convertitore copia nel JPEG il blocco EXIF originale e azzera il tag di orientamento, perché il decoder ha già ruotato l'immagine."
  - q: "Il mio HEIC contiene più immagini (Live Photo, raffica). Quale viene convertita?"
    a: "L'immagine principale, quella mostrata dall'app Foto. La parte in movimento di una Live Photo è un file video separato e non viene inclusa."
  - q: "C'è un limite di dimensione o di numero?"
    a: "Solo la memoria del dispositivo. Ogni foto viene decodificata in pixel grezzi (una foto da 12 megapixel occupa circa 48 MB durante la conversione), quindi i lotti molto grandi sono più rapidi su un computer che su un telefono datato."
  - q: "Posso convertire HEIC in PNG con trasparenza?"
    a: "Le foto delle fotocamere dei telefoni non hanno trasparenza. Se un'immagine HEIF ha un canale alfa, il PNG lo conserva; il JPEG non supporta la trasparenza e la riempie di nero."
---

## Come funziona

### Decodifica senza server

I browser diversi da Safari non aprono gli HEIC da soli, perché il formato racchiude immagini compresse in **HEVC** in un contenitore **HEIF** (ISO/IEC 23008-12). Questa pagina include **libheif** — la libreria open source di riferimento per HEIF, compilata in WebAssembly dal progetto libheif-js — e la carica solo quando trascini il primo file, così la pagina resta leggera.

Per ogni file il convertitore:

1. Legge i byte con la File API e controlla nel box `ftyp` che il brand sia HEIF (`heic`, `heix`, `mif1`…): un JPEG rinominato viene segnalato invece di bloccare il decoder.
2. Decodifica l'immagine principale con libheif in una bitmap RGBA. Rotazione e specchiatura memorizzate nel file (`irot`, `imir`) vengono applicate in questo passaggio.
3. Disegna la bitmap su un `<canvas>` e la codifica con `canvas.toBlob()` in JPEG alla qualità scelta, oppure in PNG.

### Metadati

Un canvas non porta mai metadati, quindi il file convertito è pulito per impostazione predefinita. Se scegli di mantenerli, il convertitore analizza direttamente il contenitore HEIF — il box `meta`, l'elenco degli elementi (`iinf`) e le loro posizioni (`iloc`) — per trovare l'elemento di tipo `Exif` e lo inserisce nel JPEG come segmento **APP1** standard. Nella copia il tag `Orientation` viene impostato a 1 (normale), altrimenti i visualizzatori ruoterebbero una foto già dritta. L'uscita PNG è sempre senza metadati.

### Download ZIP

Con più di un file, **Scarica tutto** carica una piccola libreria ZIP (JSZip), aggiunge ogni file convertito e salva un unico archivio. I nomi duplicati ricevono un suffisso numerico (`IMG_0001-2.jpg`).

## Casi d'uso

- **Inviare foto dell'iPhone a chi usa Windows o a moduli online** che accettano solo JPG o PNG: candidature, sinistri assicurativi, portali della pubblica amministrazione.
- **Pubblicare sul web senza rivelare la posizione.** Converti e rimuovi l'EXIF in un solo passaggio prima di caricare su un marketplace o un forum.
- **Archiviare.** Converti in JPG una cartella di foto delle vacanze per il vecchio portatile di un familiare o una cornice digitale.
- **Designer e sviluppatori** che ricevono screenshot o mockup in HEIC e hanno bisogno di PNG per la documentazione.
- **Immagini delicate** — documenti, carte d'identità, foto mediche — che non dovrebbero passare da un convertitore online che non puoi verificare.
