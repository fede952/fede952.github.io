---
title: "Convertitore HEX, RGB e HSL + Palette Neon"
description: "Converti colori tra HEX, RGB e HSL con selettore e copia in un clic, e genera palette neon cyberpunk casuali per interfacce, poster e temi. Gratis."
intro: "**NeonPalette** converte qualsiasi colore tra **HEX, RGB e HSL** mentre lo scegli o lo scrivi, e genera **palette neon** casuali di tre colori: ciano, magenta, blu elettrico, rosa shocking e simili, pensate per interfacce cyberpunk scure."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["convertitore hex rgb", "da rgb a hsl", "convertire hex in hsl", "convertitore colori", "palette colori neon", "palette cyberpunk", "selettore colori online", "colori neon hex"]
tags: ["design", "css", "colori", "strumento"]
app_category: "DesignApplication"
tool_file: "/tools/neon-palette/"
tool_title: "NeonPalette, convertitore di colori e generatore di palette"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Scegli un colore con il selettore, oppure scrivi un codice HEX a sei cifre come `#00E5FF` nel campo HEX."
  - "I campi RGB e HSL e la barra di anteprima si aggiornano subito."
  - "Premi il pulsante di copia accanto a HEX, RGB o HSL per copiare quella notazione, pronta per il CSS."
  - "Premi **Genera Palette Neon** per ottenere tre colori neon casuali di famiglie di tinte diverse."
  - "Clicca una scheda della palette per caricare quel colore nel convertitore e copiarlo nel formato che ti serve."
faq:
  - q: "Come si converte HEX in RGB?"
    a: "Un colore HEX sono tre byte scritti in esadecimale: `#RRGGBB`. Converti ogni coppia in decimale: `#00E5FF` è rosso 0x00 = 0, verde 0xE5 = 229, blu 0xFF = 255, quindi `rgb(0, 229, 255)`. La forma abbreviata a tre cifre come `#0EF` raddoppia prima ogni cifra (`#00EEFF`)."
  - q: "Cos'è HSL e perché usarlo?"
    a: "HSL descrive un colore con tinta (0–360° sulla ruota dei colori), saturazione (da 0% grigio a 100% vivido) e luminosità (da 0% nero a 100% bianco). È più intuitivo di RGB: per ottenere una versione più chiara o più spenta di un colore cambi un solo numero invece di tre."
  - q: "Cosa rende un colore \"neon\"?"
    a: "Saturazione molto alta e luminosità media su sfondo scuro. Il generatore tiene la saturazione tra 85% e 100% e la luminosità tra 45% e 60%, la fascia in cui i colori sembrano più luminosi; più chiari tendono al pastello, più scuri perdono il bagliore."
  - q: "I colori neon sono accessibili?"
    a: "Su sfondo scuro, ciano, verde e giallo neon di solito superano il contrasto WCAG per il testo grande, mentre blu, viola e magenta saturi spesso no. Usa il neon per accenti, bordi e titoli, tieni il testo corrente quasi bianco e controlla il rapporto di contrasto di ogni coppia testo/sfondo."
  - q: "Posso inserire valori RGB o HSL?"
    a: "Il convertitore prende l'input dal selettore e dal campo HEX; i campi RGB e HSL mostrano il risultato da copiare. Per partire da RGB, convertilo in HEX o impostalo nel selettore dei colori, che nella maggior parte dei browser accetta valori RGB."
  - q: "Viene salvato o inviato qualcosa?"
    a: "No. Tutte le conversioni sono semplice aritmetica in JavaScript in questa pagina, e le palette vengono generate in locale con `Math.random()`."
---

## Come funziona

### Conversioni

**HEX → RGB.** Le sei cifre esadecimali vengono lette come un unico intero a 24 bit e i tre canali estratti con spostamenti di bit: rosso = `(n >> 16) & 255`, verde = `(n >> 8) & 255`, blu = `n & 255`.

**RGB → HSL.** Ogni canale viene portato in scala 0–1. Con *max* e *min* il più grande e il più piccolo dei tre:

- **Luminosità** L = (max + min) / 2.
- **Saturazione** S = 0 per i grigi; altrimenti (max − min) / (max + min) se L ≤ 0,5, oppure (max − min) / (2 − max − min) se L > 0,5.
- **Tinta**: dipende da quale canale è il maggiore: per il rosso è (G − B) / (max − min), per il verde 2 + (B − R) / (max − min), per il blu 4 + (R − G) / (max − min), moltiplicata per 60° e riportata in 0–360°.

La tinta viene arrotondata ai gradi interi e S ed L ai punti percentuali interi, la precisione con cui si scrive di solito `hsl()` in CSS.

| Colore | HEX | RGB | HSL |
|---|---|---|---|
| Ciano neon | `#00E5FF` | 0, 229, 255 | 186°, 100%, 50% |
| Magenta acceso | `#FF2DCE` | 255, 45, 206 | 314°, 100%, 59% |
| Verde acido | `#39FF14` | 57, 255, 20 | 111°, 100%, 54% |

### Il generatore neon

Il generatore conosce otto famiglie di tinte: ciano (170–195°), magenta (290–330°), blu elettrico (210–250°), verde neon (100–150°), rosa shocking (330–355°), viola (260–290°), arancione neon (15–40°) e giallo neon (50–70°). A ogni pressione del pulsante le mescola, ne prende tre e per ognuna sceglie una tinta casuale nel suo intervallo, una saturazione dell'85–100% e una luminosità del 45–60%. I valori HSL vengono convertiti in HEX con la formula a tratti standard, così i tre colori appartengono sempre a famiglie diverse ma condividono lo stesso carattere vivido e luminoso.

## Casi d'uso

- **CSS e design token.** Converti un HEX del brand in `rgb()` per giocare con l'opacità o in `hsl()` per costruire varianti più chiare e più scure.
- **Interfacce dark e cyberpunk.** Genera colori d'accento per pulsanti, bordi, bagliori e grafici su sfondi scuri.
- **Poster, miniature e overlay per lo streaming** con un look synthwave o da insegna al neon.
- **Temi per giochi e app.** Scegli tre accenti neon complementari per un HUD, un livello o un tema da terminale.
- **Imparare i modelli di colore.** Osserva come HEX, RGB e HSL descrivono lo stesso colore e come cambiando solo la tinta ti sposti sulla ruota.
