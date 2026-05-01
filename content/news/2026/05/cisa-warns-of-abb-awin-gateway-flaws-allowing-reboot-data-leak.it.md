---
title: "CISA avverte di vulnerabilità nei gateway ABB AWIN che consentono riavvio e perdita di dati"
date: "2026-05-01T08:55:30Z"
original_date: "2026-04-30T12:00:00"
lang: "it"
translationKey: "cisa-warns-of-abb-awin-gateway-flaws-allowing-reboot-data-leak"
author: "NewsBot (Validated by Federico Sella)"
description: "I gateway ABB AWIN presentano vulnerabilità che permettono agli attaccanti di riavviare i dispositivi o estrarre la configurazione di sistema. L'avviso CISA ICSA-26-120-05 descrive CVE-2025-13777 e le relative correzioni."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05"
source: "CISA"
severity: "High"
target: "Gateway ABB AWIN"
cve: "CVE-2025-13777"
cvss: 8.3
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

I gateway ABB AWIN presentano vulnerabilità che permettono agli attaccanti di riavviare i dispositivi o estrarre la configurazione di sistema. L'avviso CISA ICSA-26-120-05 descrive CVE-2025-13777 e le relative correzioni.

{{< cyber-report severity="High" source="CISA" target="Gateway ABB AWIN" cve="CVE-2025-13777" cvss="8.3" >}}

CISA ha pubblicato l'avviso ICSA-26-120-05 che descrive multiple vulnerabilità nei gateway ABB AWIN. I difetti, che includono bypass dell'autenticazione tramite capture-replay e mancanza di autenticazione per funzioni critiche, potrebbero consentire a un attaccante non autenticato di riavviare da remoto il dispositivo o interrogare dati sensibili di configurazione del sistema. Le vulnerabilità interessano le versioni firmware AWIN 2.0-0, 2.0-1, 1.2-0 e 1.2-1 in esecuzione su hardware GW100 rev.2 e GW120.

{{< ad-banner >}}

Il problema più grave, tracciato come CVE-2025-13777, consente un'interrogazione non autenticata che rivela la configurazione di sistema, inclusi dettagli sensibili. L'avviso assegna un punteggio base CVSS v3 di 8.3, indicando alta gravità. ABB ha rilasciato la versione firmware 2.1-0 per GW100 rev.2 per correggere queste vulnerabilità. Le organizzazioni che utilizzano gateway interessati sono invitate ad applicare immediatamente l'aggiornamento.

Le vulnerabilità hanno un impatto sugli asset del settore manifatturiero critico distribuiti in tutto il mondo. Data la possibilità di sfruttamento remoto senza autenticazione, questi difetti rappresentano un rischio significativo per gli ambienti di tecnologia operativa. CISA raccomanda agli utenti di rivedere l'avviso completo e implementare mitigazioni, inclusa la segmentazione di rete e la limitazione dell'accesso ai dispositivi interessati.

{{< netrunner-insight >}}

Per gli analisti SOC: monitorare riavvii non autorizzati o interrogazioni insolite ai gateway ABB; questi sono indicatori a basso rumore di sfruttamento. I team DevSecOps dovrebbero dare priorità all'aggiornamento al firmware 2.1-0 e imporre controlli di accesso di rete rigorosi, poiché le vulnerabilità non richiedono autenticazione e possono essere sfruttate da remoto.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05)**
