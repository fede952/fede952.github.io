---
title: "Nascondere Testo in un'Immagine (LSB)"
description: "Nascondi un messaggio segreto dentro un'immagine con la steganografia LSB e rivelalo di nuovo. Esporta un PNG lossless; tutto nel browser, nessun upload."
intro: "**Steganography Lab** nasconde un messaggio di testo nei pixel di un'immagine e lo rilegge in seguito. La foto sembra identica, perché ogni valore di colore cambia al massimo di 1 su 255. Tutto avviene nel browser: immagine e messaggio non lasciano mai il tuo dispositivo."
date: 2026-02-05
lastmod: 2026-10-24
reviewed: false
keywords: ["steganografia online", "nascondere testo in immagine", "steganografia lsb", "messaggio nascosto in foto", "decodificare messaggio nascosto", "steganografia png", "messaggio segreto immagine", "strumento steganografia"]
tags: ["privacy", "sicurezza", "immagini", "strumento"]
app_category: "SecurityApplication"
tool_file: "/tools/steganography/"
tool_title: "Steganography Lab"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Nella scheda **Nascondi Messaggio** trascina un'immagine o clicca per sceglierla (JPG, PNG, WebP o GIF). Lo strumento mostra dimensioni e quanti byte può contenere."
  - "Scrivi o incolla il messaggio. La barra di capacità si riempie mentre scrivi e diventa arancione, poi rossa, avvicinandoti al limite."
  - "Clicca **Codifica e Scarica PNG**. Viene salvato un file `stego_<timestamp>.png`, visivamente identico all'originale."
  - "Invia quel PNG **come file** (allegato email, link cloud, \"invia come documento\"), non come foto che un'app di chat ricomprimerà."
  - "Per leggerlo apri la scheda **Rivela Messaggio**, carica il PNG e clicca **Decodifica Messaggio Nascosto**. Con **Copia Testo** copi il risultato."
faq:
  - q: "Il messaggio nascosto è cifrato?"
    a: "No. La steganografia nasconde l'esistenza del messaggio, non ne protegge il contenuto. Chiunque carichi il PNG in questo strumento, o conosca lo schema, può leggerlo. Per qualcosa di sensibile cifra prima il testo (ad esempio con age o GPG) e nascondi il testo cifrato."
  - q: "Perché l'output deve essere PNG?"
    a: "Il PNG è lossless: ogni valore di pixel viene salvato esattamente com'è. JPEG e WebP con perdita riquantizzano i colori al salvataggio e rimescolano proprio i bit più bassi dove vive il messaggio. Per lo stesso motivo la scheda di decodifica accetta solo PNG."
  - q: "Il messaggio è sparito dopo aver inviato l'immagine. Perché?"
    a: "La maggior parte delle app di chat e dei social ridimensiona e ricomprime le foto, e uno screenshot ridisegna i pixel. Ognuna di queste cose distrugge i bit nascosti. Invia il PNG come file o documento perché arrivi intatto byte per byte."
  - q: "Quanto testo può contenere un'immagine?"
    a: "Tre bit per ogni pixel completamente opaco, meno 19 byte di intestazione e terminatore. Una foto 1920×1080 contiene circa 777.000 byte. Il contatore è in byte UTF-8: le lettere accentate ne usano due, molte emoji quattro."
  - q: "Gli strumenti di steganalisi possono rilevarlo?"
    a: "Sì. L'inserimento LSB sequenziale è proprio il caso che test statistici come chi-quadro e analisi RS sanno individuare, soprattutto quando si usa gran parte della capacità. Consideralo uno strumento didattico e di privacy leggera, non di comunicazione occulta contro un avversario capace."
  - q: "Funziona con i PNG trasparenti?"
    a: "Sì. Solo i pixel completamente opachi trasportano dati, perché il browser memorizza i pixel semitrasparenti in forma premoltiplicata e i loro bit bassi non sopravvivrebbero. Le aree trasparenti restano intatte e riducono semplicemente la capacità."
  - q: "La mia immagine viene caricata da qualche parte?"
    a: "No. Il file viene letto con l'API FileReader ed elaborato su un canvas nella scheda del browser. Non c'è alcun server: puoi caricare la pagina, andare offline e funziona lo stesso."
---

## Come funziona

La tecnica è la **sostituzione del bit meno significativo (LSB)**, la forma classica di steganografia sulle immagini (trovi una spiegazione più ampia nella [guida Steganografia 101](/it/learn/guides/steganography-101-hidden-messages/)).

**1. Costruzione del payload.** Il testo viene codificato in UTF-8 e racchiuso così:

```
STEGO_V1::<il tuo messaggio>\0\0\0END\0\0\0
```

Il prefisso `STEGO_V1::` permette al decoder di capire subito se un'immagine contiene un messaggio; il marcatore `END` circondato da byte nulli indica dove finisce.

**2. Lettura dei pixel.** L'immagine viene disegnata su un canvas HTML alle sue dimensioni naturali, con lo smoothing disattivato, e `getImageData()` restituisce ogni pixel come byte rosso, verde, blu e alfa.

**3. Un bit per canale colore.** I bit del payload, dal più significativo, vengono scritti uno alla volta nel bit più basso dei byte R, G e B di ogni pixel completamente opaco, in ordine di lettura dall'angolo in alto a sinistra. Ogni byte diventa `(valore & 0xFE) | bit`: un canale cambia di 0 o 1 e la differenza è invisibile. L'alfa non viene mai toccato e i pixel non del tutto opachi vengono saltati, perché il canvas ne premoltiplica i colori e i bit bassi andrebbero persi.

**4. Esportazione lossless.** Il canvas modificato viene salvato con `toBlob('image/png')`. Effetto collaterale: l'output **non contiene metadati EXIF** (fotocamera, GPS, data), perché il canvas conosce solo i pixel.

**5. Decodifica.** La scheda Rivela fa il contrario: raccoglie i bit bassi degli stessi canali, ricostruisce i byte e confronta i primi dieci con `STEGO_V1::`. Se non coincidono si ferma subito, quindi una grande foto pulita viene scartata quasi all'istante; altrimenti legge fino al marcatore di fine e decodifica i byte in testo.

| Immagine | Pixel opachi | Capacità |
|---|---|---|
| 800×600 | 480.000 | ≈ 179.981 byte |
| 1920×1080 | 2.073.600 | ≈ 777.581 byte |
| 4000×3000 | 12.000.000 | ≈ 4,5 MB |

Più capacità riempi, più l'immagine è facile da segnalare con la steganalisi statistica. Un messaggio breve in una foto grande e "rumorosa" è molto più difficile da scovare di uno lungo in una grafica a tinte piatte.

## Casi d'uso

- **Studio e didattica.** Vedi esattamente cosa fa l'inserimento LSB, poi prova a romperlo: ricomprimi il PNG in JPEG e guarda il messaggio sparire.
- **Allenamento CTF.** Le sfide di steganografia nascondono spesso le flag negli LSB; codificare campioni tuoi rende lo schema facile da riconoscere con strumenti come `zsteg` o StegSolve.
- **Firmare le proprie immagini.** Inserisci una nota (autore, data) in un PNG che condividi come file. Non sopravvive alle modifiche, ma dimostra che una copia è intatta.
- **Un segreto per gioco.** Nascondi un messaggio in una foto delle vacanze per un amico che sa dove guardare.
- **Trasportare testo già cifrato.** Incolla un testo cifrato (per esempio output GPG in ASCII armor) e ottieni riservatezza e basso profilo insieme.

Per il lavoro opposto, cioè eliminare i dati nascosti nei metadati di una foto anziché nei pixel, usa l'[EXIF Cleaner](/it/tools/exif-cleaner/).
