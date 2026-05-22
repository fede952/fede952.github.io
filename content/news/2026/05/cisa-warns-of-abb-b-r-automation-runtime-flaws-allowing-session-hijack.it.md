---
title: "CISA avverte di vulnerabilità in ABB B&R Automation Runtime che consentono il dirottamento di sessione"
date: "2026-05-22T10:20:32Z"
original_date: "2026-05-21T12:00:00"
lang: "it"
translationKey: "cisa-warns-of-abb-b-r-automation-runtime-flaws-allowing-session-hijack"
author: "NewsBot (Validated by Federico Sella)"
description: "Molteplici vulnerabilità in ABB B&R Automation Runtime precedenti alla versione 6.4 potrebbero consentire a un attaccante di dirottare sessioni o eseguire codice. L'advisory CISA ICSA-26-141-04 descrive le correzioni."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04"
source: "CISA"
severity: "Medium"
target: "ABB B&R Automation Runtime"
cve: "CVE-2025-3449"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Molteplici vulnerabilità in ABB B&R Automation Runtime precedenti alla versione 6.4 potrebbero consentire a un attaccante di dirottare sessioni o eseguire codice. L'advisory CISA ICSA-26-141-04 descrive le correzioni.

{{< cyber-report severity="Medium" source="CISA" target="ABB B&R Automation Runtime" cve="CVE-2025-3449" cvss="6.1" >}}

CISA ha pubblicato l'advisory ICSA-26-141-04 che descrive molteplici vulnerabilità in ABB B&R Automation Runtime, una piattaforma software utilizzata nell'automazione industriale. I difetti, identificati dall'analisi di sicurezza interna di B&R, riguardano le versioni precedenti alla 6.4 e includono CVE-2025-3449 (identificatori di sessione prevedibili), CVE-2025-3448 (cross-site scripting) e CVE-2025-11498 (neutralizzazione impropria di elementi formula in file CSV). Un attaccante non autenticato potrebbe sfruttarli per dirottare sessioni remote o eseguire codice nel contesto del browser di un utente.

{{< ad-banner >}}

La vulnerabilità più grave, CVE-2025-3449, risiede nel componente System Diagnostic Manager (SDM) e ha un punteggio CVSS v3 di 6.1. Consente a un attaccante non autentico basato sulla rete di assumere il controllo di sessioni già stabilite a causa della generazione di numeri o identificatori prevedibili. SDM è disabilitato per impostazione predefinita in Automation Runtime 6, riducendo l'esposizione, ma le organizzazioni dovrebbero verificare che rimanga spento a meno che non sia esplicitamente necessario.

ABB ha rilasciato Automation Runtime versione 6.4 per correggere questi problemi. Dato il dispiegamento del prodotto in tutto il settore energetico mondiale, CISA esorta gli operatori ad applicare l'aggiornamento tempestivamente. L'advisory nota che uno sfruttamento riuscito potrebbe portare all'esecuzione remota di codice o al dirottamento di sessione, rappresentando un rischio significativo per gli ambienti di controllo industriale.

{{< netrunner-insight >}}

Per gli analisti SOC: dare priorità alla patch delle istanze di Automation Runtime, specialmente quelle con SDM abilitato. Il difetto di ID di sessione prevedibile (CVE-2025-3449) è banalmente sfruttabile sulla rete. I team DevSecOps dovrebbero assicurarsi che SDM rimanga disabilitato in produzione e verificare che nessuna istanza esposta sia raggiungibile da reti non fidate. Monitorare l'attività di sessione anomala come segnale di rilevamento.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04)**
