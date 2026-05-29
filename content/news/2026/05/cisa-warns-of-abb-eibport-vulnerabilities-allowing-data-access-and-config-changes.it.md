---
title: "CISA mette in guardia dalle vulnerabilità di ABB EIBPORT che consentono accesso ai dati e modifiche alla configurazione"
date: "2026-05-29T10:43:33Z"
original_date: "2026-05-28T12:00:00"
lang: "it"
translationKey: "cisa-warns-of-abb-eibport-vulnerabilities-allowing-data-access-and-config-changes"
author: "NewsBot (Validated by Federico Sella)"
description: "I dispositivi ABB EIBPORT sono vulnerabili a cross-site scripting e furto di ID di sessione. È disponibile un aggiornamento del firmware alla versione 3.9.2."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03"
source: "CISA"
severity: "High"
target: "Dispositivi ABB EIBPORT"
cve: "CVE-2021-22291"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

I dispositivi ABB EIBPORT sono vulnerabili a cross-site scripting e furto di ID di sessione. È disponibile un aggiornamento del firmware alla versione 3.9.2.

{{< cyber-report severity="High" source="CISA" target="Dispositivi ABB EIBPORT" cve="CVE-2021-22291" >}}

CISA ha pubblicato un advisory (ICSA-26-148-03) che descrive in dettaglio molteplici vulnerabilità nei dispositivi ABB EIBPORT, in particolare nei modelli EIBPORT V3 KNX e EIBPORT V3 KNX GSM. Le vulnerabilità, che includono un difetto di cross-site scripting (XSS) (CWE-79) e un problema di furto di ID di sessione (CVE-2021-22291), potrebbero consentire a un attaccante di accedere a informazioni sensibili memorizzate sul dispositivo e modificarne la configurazione.

{{< ad-banner >}}

Le versioni del firmware interessate sono quelle precedenti alla 3.9.2. ABB ha rilasciato un aggiornamento del firmware per correggere queste vulnerabilità segnalate privatamente. I prodotti sono distribuiti a livello mondiale nei settori della produzione critica e della tecnologia dell'informazione, con il produttore con sede in Svizzera.

Sebbene nell'advisory non venga fornito alcun punteggio CVSS, il potenziale impatto sull'integrità e la riservatezza del dispositivo richiede una correzione tempestiva. Le organizzazioni che utilizzano dispositivi ABB EIBPORT interessati dovrebbero applicare l'aggiornamento del firmware il prima possibile per mitigare il rischio di sfruttamento.

{{< netrunner-insight >}}

Per gli analisti SOC, dare priorità alla scansione dei dispositivi ABB EIBPORT con firmware inferiore alla 3.9.2 e monitorare eventuali modifiche anomale della configurazione o anomalie di sessione. I team DevSecOps dovrebbero integrare questo aggiornamento del firmware nella loro pipeline di gestione delle patch, specialmente considerando il ruolo del dispositivo nell'automazione degli edifici e nelle infrastrutture critiche.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03)**
