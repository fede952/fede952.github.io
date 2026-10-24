---
title: "Comprimere Immagini Online: JPG, PNG, WebP"
description: "Riduci il peso di immagini JPG, PNG e WebP nel browser: qualità, peso massimo e larghezza, conversione in WebP. Nessun upload, nessuna registrazione."
intro: "**PixelShrink** comprime e converte le immagini sul tuo dispositivo. Trascina una foto, scegli qualità, peso massimo o larghezza massima e scarica un JPG, PNG o WebP più leggero. L'immagine non viene mai caricata online."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["comprimere immagini", "ridurre peso foto", "compressore immagini online", "comprimere jpg", "comprimere png", "convertire in webp", "ridimensionare immagini", "comprimere foto senza upload"]
tags: ["immagini", "compressione", "privacy", "strumento"]
app_category: "MultimediaApplication"
tool_file: "/tools/pixel-shrink/"
tool_title: "PixelShrink, compressore di immagini"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Trascina un'immagine nell'area di caricamento o cliccaci per scegliere un file. Sono accettati PNG, JPEG, WebP e AVIF; l'anteprima mostra peso e dimensioni."
  - "Scegli il **formato di uscita**: lascia l'originale oppure converti in JPEG, PNG o WebP. Per le foto il WebP di solito è il più leggero."
  - "Imposta **qualità** (1–100, predefinita 75), un **peso massimo** in MB e una **larghezza massima** in pixel: il lato più lungo viene ridotto a quel valore mantenendo le proporzioni."
  - "Clicca **Comprimi Immagine**. Il pannello prima/dopo mostra entrambi i pesi, entrambe le dimensioni e la percentuale risparmiata."
  - "Clicca **Scarica Immagine Compressa** per salvare il risultato. Se non è più piccolo dell'originale te lo dice lo strumento: tieni l'originale o prova un altro formato."
faq:
  - q: "Le mie immagini vengono caricate su un server?"
    a: "No. L'immagine viene decodificata, ridimensionata e ricodificata dentro il tuo browser, in un Web Worker in background. Non viene inviato nulla: una volta caricata la pagina puoi anche andare offline e funziona lo stesso. Per questo va bene anche per screenshot di documenti, carte d'identità o altro di privato."
  - q: "Che qualità devo usare?"
    a: "Per le foto 70–80 è il punto giusto: il file si riduce molto e a dimensione normale le differenze si notano a fatica. Scendi a 50–60 per miniature e anteprime. Sopra 90 il file cresce in fretta senza un guadagno visibile."
  - q: "Conviene convertire in WebP?"
    a: "Per il web di solito sì. I file WebP sono in genere più leggeri del 25–35% rispetto a un JPEG di qualità simile e tutti i browser attuali li mostrano. Resta sul JPEG quando l'immagine va a un sistema che accetta solo JPG, come certi moduli di caricamento o servizi di stampa."
  - q: "Perché il mio PNG è diventato più pesante?"
    a: "Il PNG è senza perdita, quindi una fotografia salvata in PNG spesso pesa più del JPEG di partenza. PixelShrink riduce i PNG limitando la tavolozza dei colori, cosa che funziona bene per screenshot, loghi e grafica piatta e male per le foto. Per le foto scegli WebP o JPEG."
  - q: "Posso comprimere un'immagine sotto un peso preciso, per esempio 200 KB?"
    a: "Imposta **Peso massimo** a 0,2 MB. Se la prima codifica è più grande, la libreria la ripete fino a 10 volte abbassando un po' qualità e dimensioni a ogni passaggio, e si ferma appena il file rientra. Con immagini molto grandi o dettagliate può servire anche una larghezza massima più bassa."
  - q: "La compressione rimuove i dati EXIF e la posizione GPS?"
    a: "Sì. L'immagine viene ridisegnata su un canvas e ricodificata, e i metadati non vengono copiati: campi EXIF come modello della fotocamera, data e coordinate GPS spariscono. Se vuoi solo togliere i metadati senza ricomprimere, usa EXIF Cleaner."
  - q: "Perché non c'è l'uscita in AVIF?"
    a: "L'uscita è prodotta dal codificatore d'immagini del browser, e la maggior parte dei browser sa mostrare un AVIF ma non crearlo da un canvas. PixelShrink lo verifica all'avvio e mostra l'opzione AVIF solo se il tuo browser sa davvero codificarlo, invece di produrre di nascosto un PNG con estensione .avif."
---

## Come funziona

PixelShrink è un'interfaccia sottile sopra [browser-image-compression](https://github.com/Donaldcwl/browser-image-compression) (v2.0.2, ospitata su questo sito). Quando premi Comprimi il lavoro passa a un **Web Worker**, così la pagina resta reattiva anche con una foto da 20 megapixel.

1. **Decodifica.** Il file viene decodificato in bitmap con `createImageBitmap` (o con un elemento `<img>` come alternativa) e viene applicato l'orientamento EXIF, così le foto verticali non risultano ruotate.
2. **Ridimensionamento.** Se il lato più lungo supera la *larghezza massima*, l'immagine viene disegnata su un canvas più piccolo con le stesse proporzioni. Una foto 6000 × 4000 con limite 2048 px diventa 2048 × 1365.
3. **Codifica.** JPEG e WebP sono codificati dal browser (`canvas.toBlob` / `OffscreenCanvas.convertToBlob`) usando la tua impostazione di qualità. Il PNG passa da **UPNG.js**, che quantizza l'immagine a una tavolozza di al massimo 4096 × qualità colori (3.072 colori con il 75 predefinito) prima di scrivere un PNG senza perdita: è il trucco che dimezza o quasi screenshot e grafiche di interfaccia.
4. **Rientrare nel peso.** Se il risultato è ancora più grande del *peso massimo*, la codifica viene ripetuta fino a **10 volte**. A ogni passaggio la qualità viene moltiplicata per 0,95 (0,85 per il PNG) e le dimensioni possono essere scalate di 0,95, finché il file rientra o i passaggi finiscono.

Il pannello prima/dopo confronta il file originale con il risultato, e il download è un URL locale `blob:` chiamato `tuofile-compressed.<formato>`. Poiché l'immagine viene ricodificata a partire dai pixel, **metadati come EXIF e GPS non vengono riportati**.

### Quale formato scegliere

| Contenuto | Formato migliore | Perché |
|---|---|---|
| Foto per sito web o blog | WebP, qualità 70–80 | File più leggeri, supportati da tutti i browser |
| Foto per email, moduli, stampa | JPEG, qualità 75–85 | Accettato ovunque |
| Screenshot, diagrammi, loghi | PNG o WebP | Bordi netti e colori piatti si comprimono bene |
| Immagini con trasparenza | PNG o WebP | Il JPEG non ha canale alfa |

L'**AVIF** compare solo se il browser sa davvero *codificarlo* da un canvas. Oggi la maggior parte dei browser non ci riesce, e PixelShrink lo verifica all'avvio invece di tirare a indovinare.

## Casi d'uso

- **Pagine web più veloci.** Le immagini hero troppo grandi sono la causa più comune di un cattivo Largest Contentful Paint. Convertire un JPEG da 3 MB in un WebP da 2000 px a qualità 75 spesso porta sotto i 300 KB.
- **Limiti di caricamento.** Portali della pubblica amministrazione, siti di annunci di lavoro e ticket di assistenza spesso limitano gli allegati a 1 o 2 MB. Imposta il peso massimo e lascia che lo strumento trovi la qualità giusta.
- **Email e chat.** Manda cinque foto delle vacanze invece di una quando ognuna pesa un decimo dell'originale.
- **Documenti privati.** Riduci la scansione di una carta d'identità o di un contratto senza consegnarla a un servizio online di cui non sai nulla.
- **Asset per app e giochi.** Converti sprite PNG o screenshot in file più leggeri prima di metterli in un repository.
