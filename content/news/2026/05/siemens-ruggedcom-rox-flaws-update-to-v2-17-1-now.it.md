---
title: "Vulnerabilità Siemens Ruggedcom ROX: Aggiornare alla v2.17.1 Ora"
date: "2026-05-15T09:41:40Z"
original_date: "2026-05-14T12:00:00"
lang: "it"
translationKey: "siemens-ruggedcom-rox-flaws-update-to-v2-17-1-now"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA avverte di molteplici vulnerabilità di terze parti in Siemens Ruggedcom ROX precedenti alla v2.17.1. Elencati oltre 30 CVE, inclusi rischi di esecuzione remota di codice. Si consiglia l'aggiornamento immediato."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16"
source: "CISA"
severity: "High"
target: "Dispositivi Siemens Ruggedcom ROX"
cve: "CVE-2019-13103"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA avverte di molteplici vulnerabilità di terze parti in Siemens Ruggedcom ROX precedenti alla v2.17.1. Elencati oltre 30 CVE, inclusi rischi di esecuzione remota di codice. Si consiglia l'aggiornamento immediato.

{{< cyber-report severity="High" source="CISA" target="Dispositivi Siemens Ruggedcom ROX" cve="CVE-2019-13103" >}}

Le versioni di Siemens Ruggedcom ROX precedenti alla 2.17.1 contengono molteplici vulnerabilità di terze parti, come divulgato nell'avviso CISA ICSA-26-134-16. I prodotti interessati includono le serie RUGGEDCOM ROX MX5000, MX5000RE e RX1400. Siemens ha rilasciato versioni aggiornate per risolvere questi problemi e raccomanda vivamente di passare all'ultima release.

{{< ad-banner >}}

L'avviso elenca oltre 30 CVE dal 2019 al 2025, tra cui CVE-2019-13103, CVE-2022-2347 e CVE-2025-0395. Sebbene non siano forniti punteggi CVSS specifici, l'ampiezza e l'età delle vulnerabilità suggeriscono una superficie d'attacco significativa. Molti di questi CVE sono associati a componenti di terze parti e potrebbero portare a esecuzione remota di codice, denial of service o divulgazione di informazioni.

Le organizzazioni che utilizzano dispositivi Ruggedcom ROX interessati dovrebbero dare priorità alla correzione, specialmente se i dispositivi sono esposti a reti non fidate. Data la natura industriale di questi prodotti, i sistemi non aggiornati potrebbero essere sfruttati per movimento laterale o interruzione di infrastrutture critiche.

{{< netrunner-insight >}}

Questo è un classico caso di debito tecnico accumulato nei sistemi embedded. I team SOC dovrebbero inventariare tutte le istanze Ruggedcom ROX e verificare le versioni firmware. I team DevSecOps devono integrare la scansione automatica delle CVE nel loro CI/CD per le dipendenze di terze parti. La mancanza di punteggi CVSS è preoccupante: assumere il caso peggiore e trattare queste come critiche fino a prova contraria.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16)**
