---
title: "Vulnerabilità in Subnet Solutions PowerSYSTEM Center consentono fuga di informazioni e injection CRLF"
date: "2026-05-13T09:40:06Z"
original_date: "2026-05-12T12:00:00"
lang: "it"
translationKey: "subnet-solutions-powersystem-center-flaws-enable-info-leak-crlf-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA avverte di molteplici vulnerabilità in Subnet Solutions PowerSYSTEM Center, tra cui divulgazione di informazioni e injection CRLF, che interessano le versioni dal 2020 al 2026."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02"
source: "CISA"
severity: "High"
target: "Subnet Solutions PowerSYSTEM Center"
cve: "CVE-2026-35504"
cvss: 8.2
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA avverte di molteplici vulnerabilità in Subnet Solutions PowerSYSTEM Center, tra cui divulgazione di informazioni e injection CRLF, che interessano le versioni dal 2020 al 2026.

{{< cyber-report severity="High" source="CISA" target="Subnet Solutions PowerSYSTEM Center" cve="CVE-2026-35504" cvss="8.2" >}}

CISA ha pubblicato un advisory (ICSA-26-132-02) che descrive molteplici vulnerabilità in Subnet Solutions PowerSYSTEM Center, una piattaforma utilizzata nei settori della produzione critica e dell'energia. I difetti includono un'autorizzazione errata (CVE-2026-26289) che consente a utenti autenticati con permessi limitati di esportare account di dispositivi ed esporre informazioni sensibili normalmente riservate agli amministratori. Inoltre, vulnerabilità di injection CRLF (CVE-2026-35504, CVE-2026-33570, CVE-2026-35555) potrebbero permettere agli aggressori di iniettare header o risposte malevoli.

{{< ad-banner >}}

Le versioni interessate spaziano da PowerSYSTEM Center 2020 (5.8.x a 5.28.x), 2024 (6.0.x a 6.1.x) e 2026 (7.0.x). Le vulnerabilità hanno un punteggio base CVSS v3 di 8.2, indicando alta gravità. Uno sfruttamento riuscito potrebbe portare alla divulgazione di informazioni e a potenziale manipolazione delle sessioni o splitting delle risposte HTTP.

Considerando l'implementazione del prodotto in infrastrutture critiche in tutto il mondo, le organizzazioni dovrebbero dare priorità all'applicazione delle patch. Subnet Solutions ha probabilmente rilasciato aggiornamenti; si consiglia agli amministratori di consultare gli advisory di sicurezza del fornitore e applicare le patch più recenti. Fino ad allora, limitare l'accesso di rete a PowerSYSTEM Center e monitorare attività anomale.

{{< netrunner-insight >}}

Per gli analisti SOC, monitorare i log di autenticazione per esportazioni insolite di account di dispositivi: questo è un segno rivelatore dello sfruttamento di CVE-2026-26289. I team DevSecOps dovrebbero immediatamente censire le versioni di PowerSYSTEM Center e applicare le patch, poiché i vettori di injection CRLF (CVE-2026-35504 e altri) potrebbero essere concatenati con altri attacchi per compromettere l'integrità delle sessioni. Trattare questa come una remediation ad alta priorità dato il punteggio CVSS 8.2 e l'esposizione in settori critici.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02)**
