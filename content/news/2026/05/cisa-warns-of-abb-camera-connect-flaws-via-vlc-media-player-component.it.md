---
title: "CISA mette in guardia dalle vulnerabilità di ABB Camera Connect tramite il componente VLC Media Player"
date: "2026-05-27T10:51:57Z"
original_date: "2026-05-26T12:00:00"
lang: "it"
translationKey: "cisa-warns-of-abb-camera-connect-flaws-via-vlc-media-player-component"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB Ability Camera Connect versioni ≤1.5.0.14 include un VLC media player 2.2.4 vulnerabile con molteplici bug di corruzione della memoria, tra cui CVE-2024-46461, che comportano un rischio critico."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05"
source: "CISA"
severity: "Critical"
target: "ABB Ability Camera Connect"
cve: "CVE-2024-46461"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB Ability Camera Connect versioni ≤1.5.0.14 include un VLC media player 2.2.4 vulnerabile con molteplici bug di corruzione della memoria, tra cui CVE-2024-46461, che comportano un rischio critico.

{{< cyber-report severity="Critical" source="CISA" target="ABB Ability Camera Connect" cve="CVE-2024-46461" cvss="9.8" >}}

CISA ha pubblicato un avviso (ICSA-26-146-05) che descrive in dettaglio molteplici vulnerabilità in ABB Ability Camera Connect versioni 1.5.0.14 e precedenti. I difetti hanno origine da un componente di terze parti obsoleto, VLC media player versione 2.2.4, incluso nel pacchetto di installazione. Un aggiornamento alla versione 1.5.0.15 risolve il problema sostituendo il componente vulnerabile.

{{< ad-banner >}}

Le vulnerabilità includono buffer overflow basato su heap, integer underflow, scrittura fuori dai limiti, elemento del percorso di ricerca non controllato, integer overflow, errore off-by-one, lettura fuori dai limiti, double free, restrizione impropria delle operazioni all'interno dei buffer di memoria e use-after-free. In particolare, CVE-2024-46461 descrive un overflow basato su heap in VLC media player 3.0.20 e precedenti tramite un flusso MMS appositamente predisposto, che porta a denial of service.

Con un punteggio CVSS v3 di 9.8, queste vulnerabilità sono classificate come Critiche. I settori delle infrastrutture critiche interessati includono Chimico, Impianti Commerciali, Comunicazioni, Produzione Critica, Energia e Sistemi di Trasporto. Il prodotto è distribuito a livello mondiale e lo sfruttamento potrebbe consentire a un attaccante di compromettere il sistema in vari modi.

{{< netrunner-insight >}}

Questo avviso sottolinea il rischio di vulnerabilità ereditate da componenti di terze parti. Gli analisti SOC dovrebbero dare priorità alla patch di ABB Ability Camera Connect alla versione 1.5.0.15 e monitorare i tentativi di sfruttamento mirati ai difetti di VLC media player. I team DevSecOps devono imporre un controllo rigoroso delle versioni dei componenti e una scansione regolare delle librerie incluse.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05)**
