---
title: "Aim Trainer e Test dei Riflessi Online"
description: "Allena la mira col mouse in sessioni da 60 secondi: clicca i bersagli luminosi e ottieni colpi, precisione, tempo medio di reazione e un grado. Gratis."
intro: "**ReflexGrid** è un aim trainer da 60 secondi: i bersagli compaiono ovunque sulla griglia, li clicchi o tocchi il più in fretta possibile e alla fine ottieni colpi a segno, precisione, tempo medio per raggiungere il bersaglio e un grado da *Potato* a *Pro*."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["aim trainer", "test dei riflessi", "test tempo di reazione", "allenare la mira", "test precisione mouse", "aim trainer online", "allenamento fps", "test velocità click"]
tags: ["giochi", "gaming", "riflessi", "strumento"]
app_category: "GameApplication"
tool_file: "/tools/reflex-grid/"
tool_title: "ReflexGrid, aim trainer"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Premi **Start Training**. Il timer da 60 secondi parte e compare il primo bersaglio."
  - "Clicca (o tocca sugli schermi touch) ogni cerchio luminoso il più velocemente e precisamente possibile. Appena lo colpisci ne appare un altro."
  - "Tieni d'occhio la barra in alto: tempo rimasto, colpi a segno e precisione in tempo reale. I clic a vuoto abbassano la precisione."
  - "Allo scadere del tempo leggi i risultati: **Targets Hit**, **Accuracy**, **Avg Reaction** e **Total Clicks**, più il tuo grado."
  - "Premi **Play Again** per battere il tuo punteggio. Fai qualche partita di riscaldamento prima di confrontare i risultati."
faq:
  - q: "Qual è un buon tempo di reazione in questo test?"
    a: "La media qui è il tempo da quando appare il bersaglio a quando lo colpisci, quindi include lo spostamento del mouse e non solo la reazione. Sotto i 300 ms (grado *Gamer*) è buono; sotto i 200 ms (*Pro*) è eccellente. Il tempo di reazione visiva semplice di un adulto è in genere intorno ai 200–250 ms, quindi i valori di ReflexGrid sono naturalmente un po' più alti."
  - q: "Come vengono calcolati i gradi?"
    a: "Dal tempo medio per raggiungere il bersaglio: sotto i 200 ms *Pro*, sotto i 300 ms *Gamer*, sotto i 400 ms *Casual*, sotto i 500 ms *Novice* e oltre *Potato*. La precisione è mostrata a parte; per migliorare davvero, mantienila sopra l'80% circa mentre abbassi il tempo."
  - q: "La sensibilità o i DPI del mouse contano?"
    a: "Sì, moltissimo. L'allenamento della mira serve solo con la stessa sensibilità con cui giochi, quindi lascia i DPI e le impostazioni del puntatore di gioco. Disattivare \"precisione puntatore avanzata\" (l'accelerazione del mouse) su Windows rende i movimenti più costanti e più facili da allenare."
  - q: "Perché alcuni bersagli sono rossi?"
    a: "Circa il 40% dei bersagli è rosso invece che ciano, solo come variazione visiva per non farti anticipare. Valgono allo stesso modo."
  - q: "Si può giocare dal telefono?"
    a: "Sì. Il canvas ascolta sia gli eventi del mouse sia quelli touch, quindi i tocchi contano come clic. I tempi su touch non sono paragonabili a quelli col mouse: confrontati con te stesso sullo stesso dispositivo."
  - q: "I punteggi vengono salvati o inviati?"
    a: "No. Ogni sessione vive solo nella pagina; non viene salvato né inviato nulla. Annota il tuo record se vuoi seguire i progressi."
---

## Come funziona

Il gioco è disegnato su un `<canvas>` HTML scalato per il rapporto pixel del tuo schermo, con una griglia di sfondo animata e una barra HUD in alto.

**Bersagli.** Ogni bersaglio ha un raggio casuale tra 20 e 35 pixel e una posizione casuale, lontana dai bordi e dalla HUD. Pulsa del ±12%, così non sta mai perfettamente fermo. Il momento in cui compare viene salvato con `performance.now()`, l'orologio ad alta risoluzione del browser.

**Colpi e errori.** A ogni `mousedown` o `touchstart` viene calcolata con Pitagora la distanza tra il puntatore e il centro del bersaglio. Tutto ciò che sta entro 1,3 volte il raggio conta come colpo, un piccolo margine per il bagliore e la pulsazione. Un colpo registra il tempo di reazione (adesso − momento della comparsa), suona un breve tono a onda quadra ascendente generato con la Web Audio API, emette un'esplosione di particelle e fa comparire subito il bersaglio successivo. Un errore suona un tono a dente di sega discendente e aumenta solo il conteggio dei clic.

**Punteggio.** Alla fine dei 60 secondi:

- **Targets Hit** è il numero di clic riusciti;
- **Accuracy** è colpi ÷ clic totali;
- **Avg Reaction** è la media di tutti i tempi di reazione registrati, in millisecondi;
- il **grado** dipende da quella media.

| Tempo medio al bersaglio | Grado |
|---|---|
| sotto i 200 ms | Pro |
| 200–299 ms | Gamer |
| 300–399 ms | Casual |
| 400–499 ms | Novice |
| 500 ms e oltre | Potato |

Poiché ogni bersaglio compare nell'istante in cui colpisci il precedente, il test misura la velocità di *flick*: vedere un nuovo bersaglio, raggiungerlo e cliccare. È più vicino a ciò che chiedono gli FPS rispetto a un test "aspetta che lo schermo diventi verde".

## Casi d'uso

- **Riscaldamento prima degli FPS** come Valorant, CS2, Apex Legends o Overwatch: due o tre partite mettono in sintonia mano e occhi.
- **Provare un nuovo mouse o una nuova sensibilità.** Fai qualche partita con ogni impostazione e confronta precisione e tempo al bersaglio.
- **Seguire i progressi.** Annota media e precisione ogni giorno: con la pratica costante i tempi scendono a parità di precisione.
- **Una pausa veloce.** Un minuto di clic concentrati è un buon reset tra due lunghe sessioni di lavoro.
- **Controlli di ergonomia.** Un calo improvviso di precisione può essere un segnale di stanchezza: fai una pausa.
