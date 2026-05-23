---
title: "Le vulnerabilità di ABB B&R Automation Studio espongono gli ICS a esecuzione remota di codice"
date: "2026-05-23T09:00:47Z"
original_date: "2026-05-21T12:00:00"
lang: "it"
translationKey: "abb-b-r-automation-studio-flaws-expose-ics-to-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA avverte di 25 vulnerabilità in ABB B&R Automation Studio, inclusi bug critici con CVSS 9.8 che potrebbero consentire accesso non autorizzato ed esecuzione remota di codice."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03"
source: "CISA"
severity: "Critical"
target: "ABB B&R Automation Studio"
cve: "CVE-2025-6965"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA avverte di 25 vulnerabilità in ABB B&R Automation Studio, inclusi bug critici con CVSS 9.8 che potrebbero consentire accesso non autorizzato ed esecuzione remota di codice.

{{< cyber-report severity="Critical" source="CISA" target="ABB B&R Automation Studio" cve="CVE-2025-6965" cvss="9.8" >}}

CISA ha pubblicato un advisory che descrive in dettaglio molteplici vulnerabilità in ABB B&R Automation Studio, che interessano le versioni precedenti alla 6.5 e la versione 6.5. L'advisory elenca 25 CVE, tra cui CVE-2025-6965, CVE-2025-3277 e CVE-2023-7104, tra gli altri. Queste vulnerabilità derivano da componenti di terze parti obsoleti e includono problemi come buffer overflow basati su heap, scritture fuori dai limiti, use-after-free e convalida impropria degli input.

{{< ad-banner >}}

Sebbene ABB non segnali alcuna sfruttamento osservato durante i test, le vulnerabilità potrebbero rappresentare vettori di attacco per accesso non autorizzato, esposizione dei dati o esecuzione remota di codice. Le CVE più gravi hanno un punteggio CVSS v3 di 9.8, indicando una gravità critica. I prodotti interessati sono utilizzati in sistemi di automazione industriale e controllo, rendendoli bersagli attraenti per gli attori delle minacce.

ABB ha rilasciato un aggiornamento che sostituisce il componente di terze parti obsoleto. Le organizzazioni che utilizzano B&R Automation Studio sono invitate ad applicare immediatamente l'aggiornamento. Data la natura critica di queste vulnerabilità e il potenziale di sfruttamento remoto, i proprietari degli asset dovrebbero dare priorità alla patch e monitorare eventuali segni di compromissione.

{{< netrunner-insight >}}

Per gli analisti SOC e gli ingegneri DevSecOps, questo advisory sottolinea il rischio delle dipendenze da terze parti nei software ICS. Il numero elevato di CVE (25) suggerisce un problema sistemico nella gestione dei componenti. Dare priorità all'inventario delle istanze di B&R Automation Studio e applicare l'aggiornamento del fornitore. Inoltre, segmentare le reti ICS per limitare l'esposizione e implementare il monitoraggio di comportamenti anomali che potrebbero indicare tentativi di sfruttamento.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03)**
