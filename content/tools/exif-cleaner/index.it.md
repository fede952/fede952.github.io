---
title: "Rimuovere Dati EXIF e GPS dalle Foto"
description: "Guarda i metadati EXIF nascosti in una foto (posizione GPS, fotocamera, data) e scarica una copia pulita senza. Funziona offline nel browser, senza upload."
intro: "**EXIF Cleaner** mostra i metadati nascosti in una foto (coordinate GPS, modello della fotocamera, data dello scatto, software) e ti dà una copia pulita senza nessuno di questi dati. L'immagine non lascia mai il tuo dispositivo."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["rimuovere dati exif", "rimuovere metadati foto", "eliminare gps da foto", "togliere posizione da foto", "visualizzatore exif", "cancellare exif online", "metadati foto", "exif remover"]
tags: ["privacy", "osint", "immagini", "strumento"]
app_category: "SecurityApplication"
tool_file: "/tools/exif-cleaner/"
tool_title: "EXIF Cleaner: visualizza e rimuovi i metadati"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Trascina una foto nell'area di caricamento o clicca per sceglierla. Il JPEG funziona meglio; sono accettati anche PNG e WebP."
  - "Leggi la tabella **Metadati Trovati**: marca e modello della fotocamera, data dello scatto, software, esposizione, ISO, lunghezza focale, orientamento, dimensioni, copyright, autore e coordinate GPS."
  - "Se compare un avviso rosso, la foto contiene una **posizione GPS**. Le coordinate decimali indicano il punto in cui è stata scattata, con una precisione di pochi metri."
  - "Clicca **Rimuovi Metadati e Scarica**. L'immagine viene ridisegnata senza alcun metadato e salvata nello stesso formato."
  - "Clicca **Scarica Immagine Pulita** per salvare `tuofile-clean.jpg` (o .png/.webp) e condividi quella copia al posto dell'originale."
faq:
  - q: "Cosa sono i dati EXIF?"
    a: "EXIF (Exchangeable Image File Format) è un blocco di metadati che fotocamere e telefoni scrivono in ogni foto: marca e modello del dispositivo, obiettivo, impostazioni di esposizione, data e ora, software usato per modificarla e spesso le coordinate GPS del luogo dello scatto. Non si vede guardando l'immagine, ma si legge in un attimo con strumenti come questo."
  - q: "I social network rimuovono gli EXIF in automatico?"
    a: "Le grandi piattaforme come Facebook, Instagram, X e WhatsApp eliminano gran parte dei metadati dalle immagini che pubblicano. Gli allegati email, i link a cloud drive, forum, siti di annunci, app di incontri e molte app di messaggistica quando invii \"come file\" o \"qualità originale\" invece no. Nel dubbio, pulisci prima la foto."
  - q: "La mia foto viene caricata online per togliere i metadati?"
    a: "No. La lettura dei metadati e la creazione della copia pulita avvengono in JavaScript dentro questa pagina. Puoi scollegarti da internet dopo il caricamento e lo strumento continua a funzionare, quindi va bene anche per foto delicate."
  - q: "La pulizia riduce la qualità dell'immagine?"
    a: "L'uscita PNG è senza perdita. JPEG e WebP vengono ricodificati a qualità 95, praticamente indistinguibile dall'originale per quasi tutte le foto; il peso del file può cambiare di poco. La risoluzione resta identica."
  - q: "Perché il mio PNG o WebP non mostra metadati?"
    a: "Il visualizzatore usa exif-js, che legge il blocco EXIF dei file JPEG. PNG e WebP memorizzano i metadati in un altro modo e raramente contengono il GPS, quindi per loro la tabella può restare vuota. La copia pulita viene comunque ricodificata dai pixel, quindi vengono eliminati anche gli eventuali metadati che contengono."
  - q: "La foto pulita sarà ancora dritta?"
    a: "Sì. I telefoni spesso salvano le foto di lato e contano sul tag EXIF Orientation per ruotarle. Il browser applica quella rotazione quando disegna l'immagine, quindi la copia pulita ha l'orientamento corretto direttamente nei pixel e non ha più bisogno del tag."
  - q: "I metadati rimossi si possono recuperare dalla copia pulita?"
    a: "No. Il file pulito è un'immagine nuova costruita solo dai pixel: il blocco di metadati originale non viene mai copiato. Tieni l'originale se ti servono data e luogo per il tuo archivio fotografico."
---

## Come funziona

### Lettura dei metadati

Quando trascini un file, la pagina lo legge in locale con `FileReader` e lo passa a **exif-js** (v2.3.0, ospitata qui). La libreria percorre il segmento APP1 del JPEG e decodifica le directory EXIF in struttura TIFF: quella principale dell'immagine (marca, modello, software, orientamento, copyright, autore), la sottodirectory Exif (tempo di esposizione, diaframma, ISO, lunghezza focale, flash, dimensioni in pixel, spazio colore) e la directory GPS.

Le coordinate GPS sono salvate in gradi, minuti e secondi più un riferimento di emisfero (N/S, E/W). Lo strumento le converte in gradi decimali, `gradi + minuti/60 + secondi/3600`, negativi per sud e ovest, e le mostra con sei decimali, circa 10 cm di precisione. Se è presente una posizione GPS, compare l'avviso rosso.

### Creazione della copia pulita

I metadati non vengono tolti byte per byte: lo strumento butta via l'intero contenitore.

1. Il browser decodifica l'immagine in pixel grezzi.
2. Quei pixel vengono disegnati a piena risoluzione su un `<canvas>` HTML. Nel disegnarli il browser applica l'orientamento EXIF, così il risultato è dritto.
3. Il canvas viene codificato in un file completamente nuovo con `canvas.toBlob()`: **JPEG a qualità 0,95** per i JPEG, **WebP a 0,95** per i WebP e **PNG** per tutto il resto.

Un canvas contiene solo pixel, quindi il nuovo file **non ha EXIF, né GPS, né tag XMP o IPTC, né miniatura incorporata** (le vecchie miniature a volte mostrano ancora l'originale *non ritagliato*) e nessun profilo colore. Le immagini escono in sRGB, quindi le foto ad ampia gamma possono apparire appena meno sature.

Puoi verificare il risultato trascinando di nuovo nello strumento il file `-clean` scaricato: la tabella sarà vuota e l'avviso GPS non comparirà.

### Cosa non tocca

La copia pulita rimuove i *metadati*, non ciò che si vede nella foto. Un cartello stradale, un riflesso in una vetrina, una targa o un monumento riconoscibile possono ancora rivelare dove è stata scattata. Ritaglia o sfoca questi dettagli prima di condividerla.

## Casi d'uso

- **Vendere online.** Le foto degli oggetti scattate in casa possono contenere le coordinate GPS di casa tua. Puliscile prima di caricarle su un sito di annunci.
- **Mandare foto a persone che conosci poco**, come un padrone di casa, un contatto di un'app di incontri o un acquirente, senza consegnare indirizzo e modello di telefono.
- **Giornalismo e attivismo.** Togli posizione e dettagli del dispositivo da immagini che potrebbero identificare una fonte.
- **Controllare cosa stai per condividere.** Apri una foto e guarda esattamente cosa rivela: la prima volta che vedi la tua via su una mappa fa effetto.
- **Esercitarsi con l'OSINT.** Gli investigatori usano gli EXIF come indizio. Usa il visualizzatore su immagini di prova per capire cosa si può estrarre e perché pulire è importante.
