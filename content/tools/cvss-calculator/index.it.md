---
title: "Calcolatore CVSS 4.0 (con CVSS 3.1)"
description: "Calcola il punteggio CVSS 4.0 con il metodo MacroVector ufficiale di FIRST, o i punteggi CVSS 3.1 base, temporale e ambientale. Incolla un vettore o clicca."
intro: "Scegli le metriche o incolla una stringa vettore per ottenere punteggio **CVSS 4.0**, gravità, nomenclatura (CVSS-B, BT, BE o BTE) e MacroVector, calcolati con **la logica di calcolo e la tabella ufficiali di FIRST**. Una seconda scheda calcola i vettori **CVSS 3.1**, compresi punteggio temporale e ambientale. Condividi un risultato con un link `?vector=`. Tutto avviene nel browser."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["calcolatore cvss 4.0", "calcolatore cvss", "calcolo punteggio cvss", "cvss 3.1 calcolatore", "punteggio cvss vulnerabilità", "vettore cvss", "cvss 4 macrovector", "gravità vulnerabilità cvss"]
tags: ["security", "vulnerability", "cvss", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/cvss-calculator/"
tool_title: "Calcolatore CVSS 4.0 e 3.1"
tool_height: 1400
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Scegli **CVSS 4.0** o **CVSS 3.1** con le schede."
  - "Incolla una **stringa vettore** (per esempio da un bollettino di sicurezza), oppure clicca il valore di ogni metrica di base."
  - "Se vuoi, apri le metriche **di minaccia**, **ambientali** o, in 4.0, **supplementari** per adattare il punteggio al tuo ambiente."
  - "Leggi **punteggio**, **gravità** e, in 4.0, la **nomenclatura** che indica quali gruppi di metriche sono stati usati."
  - "Premi **Copia vettore** per i report, o **Copia link** per condividere una pagina che si apre con lo stesso vettore."
faq:
  - q: "Il punteggio è lo stesso del calcolatore ufficiale di FIRST?"
    a: "È calcolato con lo stesso metodo: il codice CVSS 4.0 di questo strumento è un port della funzione di calcolo del calcolatore ufficiale di FIRST e usa la sua tabella dei MacroVector senza modifiche. I test verificano tutti i vettori di esempio pubblicati nella pagina degli esempi CVSS 4.0 di FIRST e confrontano 20.000 vettori casuali con il codice ufficiale; il CVSS 3.1 è confrontato allo stesso modo con il calcolatore 3.1 di FIRST. Questo sito non è affiliato a FIRST."
  - q: "Perché CVSS 4.0 non usa una formula come la 3.1?"
    a: "CVSS 4.0 raggruppa le metriche in sei insiemi di equivalenza e associa ogni combinazione, un MacroVector, a un punteggio stabilito da esperti. Il punteggio finale parte da quello del MacroVector e viene corretto in base a quanto il vettore è lontano dal vettore più grave dello stesso MacroVector. Per questo lo strumento mostra il MacroVector accanto al punteggio."
  - q: "Cosa significano CVSS-B, CVSS-BT, CVSS-BE e CVSS-BTE?"
    a: "Indicano quali gruppi di metriche include un punteggio CVSS 4.0: B solo Base, T aggiunge le metriche di minaccia (maturità dell'exploit), E aggiunge quelle ambientali. Il punteggio di base di un bollettino è CVSS-B; aggiungendo le informazioni sugli exploit e il tuo ambiente diventa CVSS-BTE."
  - q: "Quali sono le fasce di gravità?"
    a: "La scala qualitativa è la stessa in CVSS 3.1 e 4.0: Nessuna 0.0, Bassa 0.1–3.9, Media 4.0–6.9, Alta 7.0–8.9, Critica 9.0–10.0."
  - q: "Le metriche supplementari cambiano il punteggio?"
    a: "No. Safety, Automatable, Recovery, Value Density, Vulnerability Response Effort e Provider Urgency aggiungono contesto alle decisioni ma non influiscono sul punteggio CVSS 4.0. Compaiono comunque nel vettore."
  - q: "Viene inviato qualcosa a un server?"
    a: "No. Il calcolo avviene nel browser e lo strumento non fa richieste di rete. Un link condiviso contiene solo la stringa vettore."
---

## Come funziona

### CVSS 4.0: i MacroVector e la tabella ufficiale

Le 11 metriche di base, più la maturità dell'exploit e i requisiti ambientali, vengono suddivise in sei gruppi di equivalenza (EQ1–EQ6), come "quanto è raggiungibile il sistema" (vettore di attacco, privilegi richiesti, interazione dell'utente) o "quanto è grave l'impatto sul sistema vulnerabile". Il livello di ogni gruppo forma un **MacroVector** di sei cifre, e la tabella di FIRST assegna un punteggio a ciascuno dei 270 valori possibili. Il punteggio del vettore è quel valore meno una correzione basata sulla distanza dal vettore più grave dello stesso MacroVector, arrotondato a un decimale. L'implementazione segue passo per passo il calcolatore ufficiale di FIRST e usa la sua tabella così come pubblicata (licenza BSD-2-Clause, citata nel sorgente).

### Metriche ambientali e di minaccia

Se non impostata, la **maturità dell'exploit** vale il caso peggiore (Attacked), e i requisiti di sicurezza valgono High, come prevede la specifica. Le metriche **modificate** sostituiscono la metrica di base corrispondente per il tuo ambiente: per esempio, un sistema raggiungibile solo dalla rete interna può usare Modified Attack Vector: Adjacent.

### CVSS 3.1

La seconda scheda applica le equazioni della specifica CVSS 3.1: il punteggio di base da impatto e sfruttabilità (con la correzione per l'ambito), il punteggio temporale da maturità del codice di exploit, livello di rimedio e affidabilità della segnalazione, e il punteggio ambientale con le metriche modificate e la funzione di arrotondamento della 3.1.

## Casi d'uso

- **Valutare i bollettini** — incolla il vettore di un record CVE o di un bollettino del produttore e guarda cosa determina il punteggio.
- **Valutare le tue scoperte** — per il report di un penetration test o una segnalazione di bug bounty, con un vettore che altri possono verificare.
- **Adattarlo al tuo ambiente** — usa le metriche ambientali per classificare diversamente la stessa vulnerabilità su sistemi esposti a internet e interni.
- **Confrontare 3.1 e 4.0** — molti database pubblicano ancora entrambi; valuta lo stesso problema in ciascuna scheda.
- **Imparare le metriche** — ogni valore ha un'etichetta, e il punteggio si aggiorna a ogni clic.
