---
title: "Hitachi Energy ITT600 Explorer vulnerabile a DoS a causa di difetti in libexpat"
date: "2026-06-05T10:44:09Z"
original_date: "2026-06-04T12:00:00"
lang: "it"
translationKey: "hitachi-energy-itt600-explorer-vulnerable-to-dos-via-libexpat-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA avverte di due vulnerabilità in Hitachi Energy ITT600 Explorer che potrebbero consentire attacchi denial-of-service. Colpisce le versioni precedenti alla 2.1 SP6."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02"
source: "CISA"
severity: "High"
target: "Hitachi Energy ITT600 Explorer"
cve: "CVE-2024-8176"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA avverte di due vulnerabilità in Hitachi Energy ITT600 Explorer che potrebbero consentire attacchi denial-of-service. Colpisce le versioni precedenti alla 2.1 SP6.

{{< cyber-report severity="High" source="CISA" target="Hitachi Energy ITT600 Explorer" cve="CVE-2024-8176" cvss="7.5" >}}

Hitachi Energy ha divulgato vulnerabilità nel suo prodotto ITT600 Explorer, che colpiscono specificamente le versioni precedenti alla 2.1 SP6. I difetti, identificati come CVE-2024-8176 e CVE-2025-59375, comportano ricorsione incontrollata e allocazione di risorse senza limiti o limitazioni. Questi problemi possono essere sfruttati per causare una condizione di denial-of-service (DoS).

{{< ad-banner >}}

Le vulnerabilità risiedono nella libreria libexpat utilizzata dalla funzionalità IEC61850. Un attaccante con accesso locale potrebbe inviare un messaggio IEC61850 appositamente predisposto per innescare uno stack overflow, portando potenzialmente a corruzione della memoria oltre al DoS. È importante notare che solo il prodotto ITT600 Explorer è interessato; gli endpoint del sistema IEC 61850 rimangono non influenzati.

CISA raccomanda un'azione immediata per applicare mitigazioni o aggiornamenti. Il prodotto è distribuito in tutto il mondo nel settore energetico e lo sfruttamento potrebbe interrompere le operazioni delle infrastrutture critiche. Le organizzazioni che utilizzano versioni interessate dovrebbero dare priorità alla patch e consultare l'avviso per le misure di remediation dettagliate.

{{< netrunner-insight >}}

Per gli analisti SOC, monitorare modelli di traffico IEC61850 insoliti che potrebbero indicare tentativi di sfruttamento. I team DevSecOps dovrebbero dare priorità all'aggiornamento di ITT600 Explorer alla versione 2.1 SP6 o successiva e considerare la segmentazione di rete per limitare l'accesso locale allo strumento. Dato il punteggio CVSS di 7.5 e il potenziale di corruzione della memoria, trattare questa come una patch ad alta priorità.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02)**
