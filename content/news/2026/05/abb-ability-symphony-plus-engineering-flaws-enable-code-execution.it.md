---
title: "Difetti di ABB Ability Symphony Plus Engineering Consentono Esecuzione di Codice"
date: "2026-05-02T08:20:38Z"
original_date: "2026-04-30T12:00:00"
lang: "it"
translationKey: "abb-ability-symphony-plus-engineering-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA avverte di vulnerabilità in ABB Ability Symphony Plus Engineering a causa di PostgreSQL obsoleto, che consentono l'esecuzione di codice arbitrario sui sistemi interessati."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06"
source: "CISA"
severity: "High"
target: "ABB Ability Symphony Plus Engineering"
cve: "CVE-2023-5869"
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA avverte di vulnerabilità in ABB Ability Symphony Plus Engineering a causa di PostgreSQL obsoleto, che consentono l'esecuzione di codice arbitrario sui sistemi interessati.

{{< cyber-report severity="High" source="CISA" target="ABB Ability Symphony Plus Engineering" cve="CVE-2023-5869" cvss="8.8" >}}

CISA ha pubblicato un avviso (ICSA-26-120-06) che descrive molteplici vulnerabilità in ABB Ability Symphony Plus Engineering, derivanti dall'uso di PostgreSQL versione 13.11 e precedenti. I difetti includono overflow di interi, SQL injection, race condition TOCTOU ed errori di declassamento dei privilegi, che potrebbero consentire a un utente autenticato di eseguire codice arbitrario sul sistema.

{{< ad-banner >}}

Le versioni interessate vanno da Ability Symphony Plus 2.2 fino a 2.4 SP2 RU1. Le vulnerabilità sono particolarmente preoccupanti data la distribuzione del prodotto in settori di infrastrutture critiche come Chimico, Produzione Critica, Energia e Acqua e Acque Reflue in tutto il mondo.

La vulnerabilità più rilevante, CVE-2023-5869, ha un punteggio CVSS di 8.8 e coinvolge un overflow di interi che può essere innescato da dati appositamente predisposti da un utente PostgreSQL autenticato. Uno sfruttamento riuscito potrebbe portare al compromesso completo del sistema, sottolineando la necessità di un'applicazione immediata delle patch.

{{< netrunner-insight >}}

Questo avviso sottolinea il rischio di dipendenze obsolete negli ambienti OT. Gli analisti SOC dovrebbero dare priorità alla scoperta degli asset per le istanze ABB Symphony Plus e assicurarsi che PostgreSQL sia aggiornato oltre la 13.11. I team DevSecOps devono integrare la scansione delle dipendenze nelle pipeline CI/CD per i sistemi di controllo industriale per individuare tempestivamente tali vulnerabilità ereditate.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06)**
