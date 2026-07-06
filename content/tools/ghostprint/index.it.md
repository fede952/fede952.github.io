---
title: "GhostPrint: Test dell'Impronta del Browser — Quanto Sei Tracciabile?"
description: "Scopri l'impronta invisibile che il tuo browser consegna a ogni sito — GPU, canvas, font, audio e altro — con un punteggio di unicità. 100% nel browser: nulla viene caricato."
date: 2026-07-06
tags: ["privacy", "security", "developer-tools", "fingerprinting"]
keywords: ["test impronta browser", "sono unico", "fingerprint dispositivo", "canvas fingerprint", "quanto sono tracciabile", "browser fingerprinting", "impronta webgl", "impronta audio", "test privacy online", "test anti-tracciamento"]
layout: "tool"
draft: false
tool_file: "/tools/ghostprint/"
tool_height: "2200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "GhostPrint — Test dell'Impronta del Browser", "description": "Test gratuito lato client del fingerprinting del browser: misura quanto è unico e tracciabile il tuo browser tra GPU, canvas, audio, font e altro.", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Perché un'impronta batte un cookie

I cookie sono facili da bloccare. La tua **impronta del browser** no. Il modo esatto in cui dispositivo, GPU, font, schermo e impostazioni si combinano forma un identificatore che ti segue tra i siti — e **sopravvive alla modalità in incognito, ai cookie cancellati e alla maggior parte della navigazione "privata".** GhostPrint ti mostra la tua in pochi secondi, con un punteggio di unicità e il dettaglio di ogni segnale che trapela.

Il dettaglio che chiarisce tutto: ogni segnale qui sotto viene letto **nel tuo browser** e inviato **da nessuna parte** — nessun upload, nessun log, nessun server. Ma qualsiasi sito che visiti può leggere questi stessi valori in silenzio, senza chiederti il permesso, e le reti pubblicitarie e antifrode fanno esattamente questo. Ricarica la pagina e i tuoi dati spariscono; i tracker quel pulsante non te lo offrono.

## Cosa legge GhostPrint

- **Hardware e GPU** — la scheda grafica (via WebGL), core della CPU, memoria e metriche dello schermo
- **Impronte di rendering** — hash di canvas e audio: peculiarità a livello di pixel e campione uniche del tuo sistema
- **Ambiente** — font installati, fuso orario, lingue, piattaforma e preferenze di visualizzazione
- **Segnali di privacy** — stato di cookie, Do-Not-Track e Global Privacy Control

## Come dissolvere il fantasma

- **Tor Browser** è lo standard di riferimento — ogni utente è reso deliberatamente identico agli altri.
- **Firefox** offre `privacy.resistFingerprinting`; **Brave** randomizza canvas e audio per impostazione predefinita.
- Le estensioni anti-fingerprint e la disattivazione di WebGL aiutano — e, paradossalmente, hardware esotico e font rari ti rendono *più* identificabile, non meno.

Avvia la scansione qui sopra per ottenere il tuo punteggio di unicità, poi scarica una card condivisibile e confronta gli altri tuoi browser.
