---
title: "Vulnerabilità Hitachi Energy RTU500 Consentono DoS, Impattano la Disponibilità"
date: "2026-06-05T10:46:09Z"
original_date: "2026-06-04T12:00:00"
lang: "it"
translationKey: "hitachi-energy-rtu500-vulnerabilities-allow-dos-impact-availability"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA avverte di molteplici vulnerabilità nella serie Hitachi Energy RTU500, tra cui dereferenza di puntatore NULL e ciclo infinito, con CVSS 7.8. Versioni interessate elencate."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04"
source: "CISA"
severity: "High"
target: "Firmware CMU della serie Hitachi Energy RTU500"
cve: "CVE-2025-69421"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA avverte di molteplici vulnerabilità nella serie Hitachi Energy RTU500, tra cui dereferenza di puntatore NULL e ciclo infinito, con CVSS 7.8. Versioni interessate elencate.

{{< cyber-report severity="High" source="CISA" target="Firmware CMU della serie Hitachi Energy RTU500" cve="CVE-2025-69421" cvss="7.8" >}}

Hitachi Energy ha divulgato molteplici vulnerabilità che interessano il firmware CMU della serie RTU500. I difetti includono dereferenza di puntatore NULL, overflow o wraparound di interi e ciclo con condizione di uscita irraggiungibile (ciclo infinito), che potrebbero portare a condizioni di denial of service. Lo sfruttamento impatta principalmente la disponibilità del prodotto, con potenziali effetti secondari su riservatezza e integrità.

{{< ad-banner >}}

L'avviso, pubblicato da CISA (ICSA-26-155-04), elenca le versioni firmware interessate dalla 12.7.1 alla 13.8.1. Sono associate molteplici CVE, tra cui CVE-2025-69421, CVE-2026-24515, CVE-2026-25210, CVE-2026-32776, CVE-2026-32777, CVE-2026-32778 e CVE-2026-8479. Le vulnerabilità hanno un punteggio base CVSS v3 di 7.8, indicando alta gravità.

Hitachi Energy raccomanda un'azione immediata secondo le linee guida di remediation dell'avviso. Dato il contesto delle infrastrutture critiche, le organizzazioni che utilizzano versioni RTU500 interessate dovrebbero dare priorità alla patch e implementare la segmentazione di rete per mitigare il rischio di sfruttamento.

{{< netrunner-insight >}}

Queste vulnerabilità ricordano che i dispositivi OT spesso sono in ritardo nei cicli di patch. I team SOC dovrebbero monitorare il traffico anomalo verso le unità RTU500 e assicurarsi che questi dispositivi siano isolati dalle reti non fidate. Gli ingegneri DevSecOps dovrebbero integrare la scansione del firmware nelle pipeline CI/CD per rilevare CVE note prima del deployment.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04)**
