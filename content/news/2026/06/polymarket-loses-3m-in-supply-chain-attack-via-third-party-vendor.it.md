---
title: "Polymarket perde 3 milioni di dollari in un attacco alla supply chain tramite un fornitore terzo"
date: "2026-06-28T09:58:42Z"
original_date: "2026-06-26T18:04:12"
lang: "it"
translationKey: "polymarket-loses-3m-in-supply-chain-attack-via-third-party-vendor"
author: "NewsBot (Validated by Federico Sella)"
description: "Gli hacker hanno iniettato uno script dannoso nel frontend di Polymarket dopo aver violato un fornitore terzo, causando perdite per 3 milioni di dollari ai clienti. La piattaforma rimborserà completamente le vittime."
original_url: "https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Utenti del frontend di Polymarket"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Gli hacker hanno iniettato uno script dannoso nel frontend di Polymarket dopo aver violato un fornitore terzo, causando perdite per 3 milioni di dollari ai clienti. La piattaforma rimborserà completamente le vittime.

{{< cyber-report severity="High" source="BleepingComputer" target="Utenti del frontend di Polymarket" >}}

Polymarket, una piattaforma di mercato predittivo decentralizzato, ha rivelato che gli aggressori hanno compromesso un fornitore terzo per iniettare uno script dannoso nel suo frontend, causando una perdita stimata di 3 milioni di dollari per i clienti. L'incidente, descritto come un attacco alla supply chain, ha preso di mira l'interfaccia utente della piattaforma per sottrarre fondi.

{{< ad-banner >}}

L'azienda ha dichiarato che rimborserà completamente i clienti colpiti, sebbene il numero esatto delle vittime non sia stato reso noto. La violazione evidenzia i rischi associati alle dipendenze da terze parti nelle piattaforme DeFi e crypto, dove l'integrità del frontend è cruciale per la sicurezza delle transazioni.

Sebbene non siano stati forniti CVE o punteggio CVSS specifici, il vettore dell'attacco—compromettere un fornitore per alterare il codice del frontend—sottolinea la necessità di misure robuste di sicurezza della supply chain, tra cui firma del codice, controlli di integrità e valutazioni del rischio dei fornitori.

{{< netrunner-insight >}}

Questo incidente è un classico attacco alla supply chain che mira all'integrità del frontend. Gli analisti SOC dovrebbero monitorare le iniezioni di script non autorizzate nelle applicazioni web, specialmente quelle che si affidano a librerie di terze parti o CDN. I team DevSecOps devono imporre politiche di sicurezza dei contenuti (CSP) rigorose, controlli di integrità delle sotto-risorse (SRI) e audit regolari dei fornitori per mitigare tali rischi.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/)**
