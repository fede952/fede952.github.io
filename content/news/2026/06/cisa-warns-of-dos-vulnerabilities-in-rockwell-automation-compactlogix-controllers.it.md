---
title: "CISA avverte di vulnerabilità DoS nei controller Rockwell Automation CompactLogix"
date: "2026-06-17T11:46:16Z"
original_date: "2026-06-16T12:00:00"
lang: "it"
translationKey: "cisa-warns-of-dos-vulnerabilities-in-rockwell-automation-compactlogix-controllers"
author: "NewsBot (Validated by Federico Sella)"
description: "Multiple vulnerabilità nei controller Rockwell Automation CompactLogix 5370 potrebbero consentire attacchi denial-of-service. CVE-2025-11694 è tra i difetti."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04"
source: "CISA"
severity: "High"
target: "Controller Rockwell Automation CompactLogix 5370"
cve: "CVE-2025-11694"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Multiple vulnerabilità nei controller Rockwell Automation CompactLogix 5370 potrebbero consentire attacchi denial-of-service. CVE-2025-11694 è tra i difetti.

{{< cyber-report severity="High" source="CISA" target="Controller Rockwell Automation CompactLogix 5370" cve="CVE-2025-11694" cvss="7.5" >}}

CISA ha pubblicato un advisory (ICSA-26-167-04) che descrive vulnerabilità nei controller Rockwell Automation CompactLogix 5370 (L1, L2, L3). I difetti includono una convalida impropria dei valori di integrità e l'esposizione di informazioni sensibili di sistema, che potrebbero consentire a un attaccante di causare una condizione di denial-of-service. L'advisory interessa le versioni precedenti alla V38.011.

{{< ad-banner >}}

La vulnerabilità più rilevante, CVE-2025-11694, riguarda la mancata convalida dei numeri di sequenza e degli indirizzi IP sorgente nel protocollo CIP. Un attaccante può sfruttare gli ID di connessione esposti visibili nell'interfaccia web per effettuare attacchi denial-of-service, causando un guasto minore. Il punteggio CVSS v3 per questa vulnerabilità è 7.5.

Rockwell Automation raccomanda di aggiornare alla versione V38.011 per risolvere questi problemi. I prodotti interessati sono distribuiti in tutto il mondo nel settore Critical Manufacturing. Le organizzazioni dovrebbero dare priorità alla correzione di questi controller per mitigare potenziali interruzioni operative.

{{< netrunner-insight >}}

Per gli analisti SOC, monitorare modelli di traffico CIP insoliti o tentativi di connessione ripetuti verso i controller CompactLogix. Gli ingegneri DevSecOps devono assicurarsi che l'interfaccia web non sia esposta a reti non fidate e applicare tempestivamente l'aggiornamento firmware alla V38.011. Si tratta di un vettore DoS semplice che può essere mitigato con una corretta segmentazione di rete e gestione delle patch.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04)**
