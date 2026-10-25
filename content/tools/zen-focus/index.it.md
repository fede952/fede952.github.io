---
title: "Timer di Concentrazione e Rumore Bianco"
description: "Mixa rumore bianco, rosa e marrone, pioggia, camino, tastiera e caffè, e avvia un timer Pomodoro. Suoni generati in tempo reale nel browser, senza file."
intro: "**ZenFocus** unisce un timer di concentrazione a un mixer di suoni ambientali a otto canali. Scegli un preset o crea il tuo mix di rumore, pioggia, camino, tasti e brusio da bar, poi avvia una sessione da 25 minuti. Ogni suono è generato in tempo reale nel browser: nessun file audio da scaricare e nessun account."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["timer concentrazione", "timer pomodoro online", "mixer suoni ambientali", "rumore marrone", "rumore bianco online", "rumore rosa", "suono pioggia per studiare", "rumore di sottofondo per concentrarsi"]
tags: ["produttività", "concentrazione", "audio", "strumento"]
app_category: "UtilitiesApplication"
tool_file: "/tools/zen-focus/"
tool_title: "ZenFocus, timer e mixer di rumori"
tool_height: 800
tool_sandbox: "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
tool_allow: "clipboard-write; web-share"
howto:
  - "Scegli un preset: **Deep Work** (rumore marrone e pioggia), **Coffee Break** (brusio da bar e camino) o **Silence** per azzerare tutti i canali."
  - "Oppure crea il tuo mix spostando il cursore di ogni scheda. Il pulsante 🔊 di una scheda silenzia quel canale senza perdere il livello."
  - "Regola il volume generale con il cursore **Master**. Parti basso: il rumore di mascheramento funziona meglio quando copre appena le distrazioni."
  - "Imposta la durata con **−5**, **−1**, **+1** e **+5** (da 1 a 90 minuti, predefinito 25), poi premi **Start**."
  - "Lavora fino al rintocco. **Pause** ferma il tempo e **Reset** ripristina la durata piena. Per una pausa imposta 5 minuti e riparti."
faq:
  - q: "Che differenza c'è tra rumore bianco, rosa e marrone?"
    a: "Cambia il modo in cui l'energia si distribuisce sulle frequenze. Il rumore bianco ha la stessa potenza a ogni frequenza e suona sibilante. Il rosa perde circa 3 dB per ottava, quindi è più morbido, simile a una pioggia costante. Il marrone (browniano) perde circa 6 dB per ottava e suona come un rombo profondo o una cascata lontana. Molti trovano rosa e marrone meno stancanti del bianco nelle sessioni lunghe."
  - q: "Il rumore di sottofondo migliora davvero la concentrazione?"
    a: "Le prove sono contrastanti. Un rumore costante maschera in modo affidabile i suoni imprevedibili, come voci e notifiche, che sono ciò che di solito interrompe la concentrazione. Alcuni studi riportano benefici per l'attenzione, soprattutto in persone con ADHD; altri non trovano effetti o un peggioramento nella lettura complessa. Consideralo un esperimento personale: prova un mix per una settimana e tienilo se ti aiuta."
  - q: "Cos'è la Tecnica del Pomodoro?"
    a: "Un metodo di gestione del tempo ideato da Francesco Cirillo: lavori su un compito per 25 minuti, fai 5 minuti di pausa e, dopo quattro cicli, una pausa più lunga di 15–30 minuti. ZenFocus parte da 25 minuti; per le pause imposta 5. Non cambia automaticamente, così decidi tu quando iniziare il ciclo successivo."
  - q: "Il timer continua in una scheda in background?"
    a: "Sì. Il conto alla rovescia è calcolato da un orario di fine fisso e non contando i tick, quindi resta preciso anche quando il browser rallenta i timer delle schede nascoste. Il rintocco suona allo scadere, purché la scheda sia ancora aperta."
  - q: "Perché non si sente nulla finché non clicco?"
    a: "I browser bloccano l'audio finché non interagisci con la pagina. ZenFocus avvia il motore audio al primo clic su un cursore, un preset o Start, poi alza i canali in dissolvenza."
  - q: "I suoni sono registrazioni?"
    a: "No. Ogni canale è sintetizzato con la Web Audio API: buffer di rumore modellati da filtri (la pioggia, per esempio, è rumore bianco passa-alto e il tuono rumore marrone passa-basso), mentre la tastiera è una serie di brevi clic casuali. Nulla viene scaricato o trasmesso, quindi funziona anche offline una volta caricata la pagina."
  - q: "È sicuro ascoltare per ore?"
    a: "Tieni il volume moderato. Una regola comune è restare a un livello in cui senti ancora qualcuno che ti parla accanto, e fare pause regolari. L'esposizione prolungata a suoni forti in cuffia può danneggiare l'udito."
---

## Come funziona

ZenFocus è una singola pagina basata sulla **Web Audio API**. Alla prima interazione crea un `AudioContext` e genera in memoria alcuni secondi di rumore grezzo:

- **Rumore bianco**: campioni casuali uniformi tra −1 e 1, quindi uno spettro piatto.
- **Rumore rosa**: il noto filtro di Paul Kellet, un banco di filtri del primo ordine che approssima una pendenza di −3 dB/ottava.
- **Rumore marrone**: un "integratore con perdita" che accumula passi casuali, con pendenza di −6 dB/ottava.
- **Clic di tastiera**: circa cinque brevi impulsi al secondo, a decadimento esponenziale e volume casuale.

I buffer rosa e marrone vengono corretti perché l'ultimo campione coincida con il primo, così il punto di loop non produce clic. Ognuno degli otto canali è una sorgente in loop, eventualmente filtrata da un biquad, poi un nodo di guadagno (il cursore della scheda) e infine il guadagno master:

| Canale | Sorgente | Filtro |
|---|---|---|
| White Noise | bianco | nessuno |
| Pink Noise | rosa | nessuno |
| Brown Noise | marrone | nessuno |
| Rain | bianco | passa-alto 1,2 kHz |
| Thunder | marrone | passa-basso 100 Hz |
| Fireplace | bianco | passa-banda 700 Hz |
| Keyboard | clic | passa-banda 2,2 kHz |
| Coffee Shop | rosa | passa-banda ampio 1 kHz |

Tutti i canali girano fin dall'inizio; spostare un cursore cambia solo il suo guadagno, con una rampa di 50 ms che evita schiocchi. Il mute porta il guadagno a zero ma ricorda il valore del cursore.

**Il timer** memorizza l'istante in cui la sessione deve finire e ricalcola il tempo rimasto quattro volte al secondo. I browser possono rallentare `setInterval` nelle schede in background, ma poiché il display deriva dall'orologio e non dai tick contati, una sessione da 25 minuti finisce dopo 25 minuti. A zero, tre toni sinusoidali (un arpeggio di La maggiore: 880, 1109 e 1319 Hz) suonano come un rintocco morbido.

Il pulsante Share usa il pannello di condivisione nativo del dispositivo quando c'è, altrimenti copia il link della pagina. Nient'altro lascia la pagina: impostazioni e utilizzo non vengono salvati.

## Casi d'uso

- **Blocchi di lavoro profondo.** Avvia Deep Work, imposta 50 minuti e chiudi tutto il resto: il rombo costante copre chiacchiere d'ufficio e rumore della strada.
- **Studiare con il metodo Pomodoro.** Alterna sessioni da 25 minuti e pause da 5, con una pausa più lunga dopo quattro cicli.
- **Open space e case condivise.** Rumore rosa o marrone in cuffia a basso volume copre il parlato intelligibile, il suono più distraente per la maggior parte delle persone.
- **Scrivere e leggere.** Un mix leggero Coffee Shop + Fireplace crea un'atmosfera da caffè senza testi di canzoni che rubano attenzione.
- **Rilassarsi a fine giornata.** Pioggia e rumore marrone sono uno sfondo calmo per leggere prima di dormire; usa il timer per smettere di scorrere il telefono.
- **Timeboxing di commissioni e riunioni.** Imposta 10 o 15 minuti per un'attività che rimandi sempre: il rintocco ti dice quando fermarti.
