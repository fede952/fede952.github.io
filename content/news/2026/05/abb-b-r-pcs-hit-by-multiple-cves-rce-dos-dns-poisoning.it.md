---
title: "PC industriali ABB B&R colpiti da molteplici CVE: RCE, DoS, avvelenamento DNS"
date: "2026-05-22T10:21:58Z"
original_date: "2026-05-21T12:00:00"
lang: "it"
translationKey: "abb-b-r-pcs-hit-by-multiple-cves-rce-dos-dns-poisoning"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA avverte di vulnerabilità nei PC industriali ABB B&R. È disponibile un aggiornamento. Gli attaccanti possono ottenere esecuzione di codice remoto, DoS, avvelenamento della cache DNS o furto di dati."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02"
source: "CISA"
severity: "High"
target: "PC industriali ABB B&R"
cve: "CVE-2023-45229"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA avverte di vulnerabilità nei PC industriali ABB B&R. È disponibile un aggiornamento. Gli attaccanti possono ottenere esecuzione di codice remoto, DoS, avvelenamento della cache DNS o furto di dati.

{{< cyber-report severity="High" source="CISA" target="PC industriali ABB B&R" cve="CVE-2023-45229" >}}

ABB ha divulgato vulnerabilità che interessano diverse linee di prodotti PC industriali B&R, tra cui APC4100, APC910, C80, MPC3100, PPC1200, PPC900 e APC2200. I difetti, tracciati come CVE-2023-45229 fino a CVE-2023-45237, consentono agli attaccanti in rete di eseguire codice remoto, lanciare attacchi denial-of-service, avvelenare le cache DNS o estrarre informazioni sensibili.

{{< ad-banner >}}

L'avviso elenca le versioni interessate per ciascun prodotto, con aggiornamenti disponibili per risolvere i problemi. Ad esempio, le versioni di APC4100 inferiori alla 1.09 sono vulnerabili, mentre la versione 1.09 è corretta. Allo stesso modo, le versioni di APC910 fino alla 1.25 incluse sono interessate. ABB raccomanda di aggiornare immediatamente all'ultima versione del firmware.

Dato il contesto dei sistemi di controllo industriale (ICS), queste vulnerabilità comportano rischi significativi per gli ambienti di tecnologia operativa. Le organizzazioni che utilizzano PC ABB B&R interessati dovrebbero dare priorità alla correzione, specialmente se i dispositivi sono esposti a reti non fidate.

{{< netrunner-insight >}}

Per gli analisti SOC, monitorare il traffico di rete per query DNS anomale o connessioni inaspettate dai PC B&R. I team DevSecOps dovrebbero inventariare tutti i dispositivi interessati e applicare gli aggiornamenti del firmware il prima possibile, poiché queste CVE consentono l'esecuzione di codice remoto senza autenticazione. Considerare la segmentazione delle reti ICS per limitare l'esposizione.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02)**
