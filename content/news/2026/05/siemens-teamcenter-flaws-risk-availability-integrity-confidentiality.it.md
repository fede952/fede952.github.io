---
title: "Vulnerabilità in Siemens Teamcenter mettono a rischio disponibilità, integrità e riservatezza"
date: "2026-05-16T08:47:33Z"
original_date: "2026-05-14T12:00:00"
lang: "it"
translationKey: "siemens-teamcenter-flaws-risk-availability-integrity-confidentiality"
author: "NewsBot (Validated by Federico Sella)"
description: "Molteplici vulnerabilità in Siemens Teamcenter potrebbero compromettere disponibilità, integrità e riservatezza. Aggiornare immediatamente alle versioni più recenti."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04"
source: "CISA"
severity: "High"
target: "Siemens Teamcenter"
cve: "CVE-2024-4367"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Molteplici vulnerabilità in Siemens Teamcenter potrebbero compromettere disponibilità, integrità e riservatezza. Aggiornare immediatamente alle versioni più recenti.

{{< cyber-report severity="High" source="CISA" target="Siemens Teamcenter" cve="CVE-2024-4367" cvss="7.5" >}}

Siemens Teamcenter è affetto da molteplici vulnerabilità che potrebbero portare alla compromissione di disponibilità, integrità e riservatezza. I difetti includono controllo improprio per condizioni anomale o eccezionali, cross-site scripting e uso di credenziali hard-coded. Le versioni interessate includono Teamcenter V2312, V2406, V2412, V2506 e V2512.

{{< ad-banner >}}

CVE-2024-4367 è un controllo del tipo mancante durante la gestione dei font in PDF.js, che consente l'esecuzione arbitraria di JavaScript nel contesto di PDF.js. Questa vulnerabilità interessa Firefox e Thunderbird ma è elencata nell'avviso Siemens. Siemens raccomanda di aggiornare alle versioni più recenti di Teamcenter per mitigare questi rischi.

Le vulnerabilità hanno un punteggio base CVSS v3 di 7.5, indicando alta gravità. I settori manifatturieri critici sono interessati, con distribuzione mondiale. Le organizzazioni dovrebbero dare priorità alla correzione e rivedere la propria esposizione a queste vulnerabilità.

{{< netrunner-insight >}}

Gli analisti SOC dovrebbero inventariare immediatamente tutte le istanze di Teamcenter e dare priorità all'aggiornamento alle versioni più recenti. I team DevSecOps devono verificare che i componenti PDF.js siano aggiornati e monitorare i tentativi di sfruttamento mirati a queste CVE. Dato l'alto punteggio CVSS e il potenziale di compromissione totale, trattare questa come una correzione ad alta priorità.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04)**
