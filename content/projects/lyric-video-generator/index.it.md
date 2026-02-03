---
title: "FLAC Lyric Video Generator"
date: 2025-01-11
draft: false
description: "Un tool di automazione per audiofili che permette di unire audio FLAC lossless e testi sincronizzati per i sistemi di bordo auto."
tags: ["FFmpeg", "PowerShell", "Automazione", "Car Audio"]
categories: ["Progetti", "Sviluppo"]
externalLink: "https://github.com/fede952/Lyric-video-generator"
---

### Automazione per l'Intrattenimento Audio Lossless in Auto

**Descrizione del Progetto**
I moderni sistemi di infotainment automobilistici (come l'Audi MIB3) supportano nativamente i file audio FLAC, ma spesso non sono in grado di leggere i file di testo sincronizzati (`.lrc`). Questo progetto nasce per risolvere questo problema, dedicato agli audiofili che non vogliono scendere a compromessi sulla qualità.

Ho sviluppato un tool di automazione "zero-dependency" che unisce l'audio lossless e i testi sincronizzati all'interno di un contenitore video. La filosofia alla base è l'integrità **Bit-Perfect**: il flusso audio viene copiato direttamente senza ricompressione, mentre i testi vengono impressi ("burned-in") nel flusso video tramite script, garantendo la compatibilità con qualsiasi lettore, indipendentemente dal supporto nativo per i sottotitoli.

**Funzionalità Principali**

* **Preservazione Audio Lossless:** Utilizza il codec `copy` di FFmpeg per mantenere la qualità FLAC originale 1:1.
* **Rendering Dinamico dei Testi:** Analizza i file `.lrc` standard per creare una visualizzazione stile karaoke a doppia linea (linea attuale evidenziata, successiva in ombra).
* **Automazione Intelligente:** Scansiona ricorsivamente le cartelle per processare intere discografie in batch.
* **Customizzazione Visiva:** Supporta sfondi personalizzati (es. texture fibra di carbonio) con oscuramento automatico per garantire la leggibilità del testo.

**Tecnologie Utilizzate**

* **Logica Core:** PowerShell & Batch Scripting
* **Elaborazione Media:** FFmpeg (CLI)
* **Data Formatting:** Logica di conversione da LRC a ASS (Advanced Substation Alpha)

[Vedi su GitHub](https://github.com/fede952/Lyric-video-generator)