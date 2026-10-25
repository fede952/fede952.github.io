---
title: "Effetto Glitch per Foto Online"
description: "Aggiungi effetti glitch alle foto: RGB shift, pixel sorting, scanline e rumore digitale, con preset VHS e cyberpunk. PNG a piena risoluzione, senza upload."
intro: "**GlitchForge** trasforma una foto in glitch art: separazione cromatica RGB, pixel sorting, scanline da CRT e rumore digitale, dosati con quattro cursori o con preset a un clic. L'immagine viene elaborata su un canvas nel tuo browser ed esportata come PNG a piena risoluzione."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["effetto glitch", "glitch art online", "effetto rgb split", "pixel sorting online", "effetto vhs foto", "effetto cyberpunk foto", "aberrazione cromatica effetto", "foto glitch"]
tags: ["immagini", "design", "creatività", "strumento"]
app_category: "MultimediaApplication"
tool_file: "/tools/glitch-forge/"
tool_title: "GlitchForge, generatore di glitch art"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Trascina un JPEG, PNG o WebP nell'area del canvas o clicca per sceglierlo."
  - "Prova prima un preset: **VHS**, **Cyberpunk**, **Corrupt** o **Subtle**."
  - "Rifinisci con i cursori: **Amount** (contrasto, rumore e strappi), **RGB Shift**, **Scanlines** e **Pixel Sort**. L'anteprima si aggiorna mentre trascini."
  - "Premi **Download Cyberpunk Image** per salvare `glitchforge-export.png` alla risoluzione originale."
  - "Premi **Reset Image** per riportare tutti i cursori a zero e ricominciare."
faq:
  - q: "La mia foto viene caricata da qualche parte?"
    a: "No. L'immagine viene disegnata su un canvas HTML e ogni effetto è calcolato sui suoi pixel in JavaScript, nel tuo browser. Nulla viene inviato a un server, quindi puoi usarlo tranquillamente con foto personali."
  - q: "Che risoluzione ha il download?"
    a: "Quella originale. L'anteprima è ridotta per stare sullo schermo, ma l'esportazione ridisegna l'immagine a piena larghezza e altezza, applica le stesse impostazioni e salva un PNG senza perdita."
  - q: "Perché il download è un po' diverso dall'anteprima?"
    a: "Il rumore e gli strappi orizzontali sono casuali e vengono rigenerati per l'esportazione, a una dimensione diversa. Il carattere dell'effetto è lo stesso, ma i singoli pixel di rumore e la posizione delle barre cambiano, come succede anche ogni volta che muovi un cursore."
  - q: "Cos'è il pixel sorting?"
    a: "Un effetto reso popolare da artisti glitch come Kim Asendorf: i pixel di una zona vengono riordinati per luminosità, e le aree chiare si allungano in strisce. GlitchForge ordina in verticale i tratti di pixel luminosi, così le luci colano verso il basso mentre le zone scure restano intatte."
  - q: "Cos'è l'effetto RGB shift?"
    a: "Imita l'aberrazione cromatica o un segnale analogico disallineato: il canale rosso viene spostato a destra e il blu a sinistra, lasciando frange colorate su ogni bordo. Alla massima intensità lo spostamento è il 4% della larghezza dell'immagine."
  - q: "Posso usare le immagini a scopo commerciale?"
    a: "Il risultato è la tua foto trasformata da un algoritmo, quindi i diritti sono quelli dell'immagine originale. Lo strumento non aggiunge filigrane e non rivendica nulla sul risultato."
---

## Come funziona

Quando carichi un file, l'immagine viene disegnata su un canvas ridimensionato per l'anteprima e ne viene conservata una copia pulita dei pixel (`getImageData`). A ogni movimento di un cursore gli effetti vengono applicati a una copia fresca di quei pixel, in quest'ordine:

1. **Amount: contrasto e rumore.** Ogni canale di colore viene allontanato dal grigio medio con un fattore di contrasto fino a 1,6×, poi si aggiunge un rumore casuale fino a ±20 livelli e il valore viene limitato a 0–255.
2. **RGB shift.** Si copia il buffer dei pixel; per ogni pixel il rosso viene letto da un pixel *shift* colonne più a sinistra e il blu da *shift* colonne più a destra, con *shift* = RGB × 4% della larghezza. Il verde resta fermo, e così nascono le frange rosse e blu.
3. **Pixel sort.** Una colonna ogni due viene percorsa dall'alto in basso. Dove la luminanza (0,299 R + 0,587 G + 0,114 B, i pesi Rec. 601) supera una soglia di 1 − Sort, il tratto di pixel luminosi, lungo al massimo metà dell'altezza × Sort, viene raccolto e riordinato dal più scuro al più chiaro.
4. **Scanline.** Linee nere orizzontali alte un pixel, ogni 2–4 pixel, vengono disegnate sopra con un'opacità fino al 50%, come su uno schermo CRT.
5. **Strappi.** Quando Amount supera il 25%, fino a otto sottili strisce orizzontali casuali vengono copiate e spostate di lato: il classico "tracking" delle videocassette.

I preset sono solo posizioni dei cursori:

| Preset | Amount | RGB | Scanlines | Sort |
|---|---|---|---|---|
| VHS | 45 | 60 | 70 | 10 |
| Cyberpunk | 65 | 80 | 40 | 35 |
| Corrupt | 85 | 50 | 20 | 90 |
| Subtle | 20 | 25 | 15 | 5 |

Il rendering è pianificato con `requestAnimationFrame`, quindi trascinare un cursore ridisegna al massimo una volta per frame. Per il download, un secondo canvas alla dimensione originale esegue la stessa pipeline e viene salvato con `toDataURL('image/png')`.

## Casi d'uso

- **Copertine, poster e miniature** con un look synthwave, VHS o cyberpunk, senza aprire un editor pesante.
- **Post sui social.** Un'immagine del profilo glitchata o uno sfondo per le storie si fanno notare nel feed.
- **Asset per giochi e app.** Crea sfondi da schermo corrotto, schermate di errore o texture di interfacce "hackerate".
- **Esplorazione grafica.** Pixel sorting e spostamento dei canali generano in fretta texture astratte da foto qualsiasi.
- **Insegnare l'elaborazione delle immagini.** Ogni cursore è un'operazione classica sui pixel; attivarli uno alla volta mostra che un'immagine è solo una matrice di numeri.
