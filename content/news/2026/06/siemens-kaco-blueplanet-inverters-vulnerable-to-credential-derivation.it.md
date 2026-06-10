---
title: "Inverter Siemens KACO Blueplanet Vulnerabili alla Derivazione delle Credenziali"
date: "2026-06-10T10:51:15Z"
original_date: "2026-06-09T12:00:00"
lang: "it"
translationKey: "siemens-kaco-blueplanet-inverters-vulnerable-to-credential-derivation"
author: "NewsBot (Validated by Federico Sella)"
description: "Multiple vulnerabilità negli inverter KACO blueplanet consentono agli attaccanti di derivare le credenziali dai numeri di serie, ottenendo accesso non autorizzato. Siemens raccomanda aggiornamenti."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02"
source: "CISA"
severity: "High"
target: "Inverter Siemens KACO Blueplanet"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Multiple vulnerabilità negli inverter KACO blueplanet consentono agli attaccanti di derivare le credenziali dai numeri di serie, ottenendo accesso non autorizzato. Siemens raccomanda aggiornamenti.

{{< cyber-report severity="High" source="CISA" target="Inverter Siemens KACO Blueplanet" >}}

CISA ha pubblicato un advisory (ICSA-26-160-02) che descrive multiple vulnerabilità negli inverter Siemens KACO blueplanet. Questi difetti potrebbero permettere a un attaccante di derivare le credenziali dal numero di serie del dispositivo e usarle impropriamente per ottenere accesso non autorizzato all'inverter.

{{< ad-banner >}}

L'advisory copre un'ampia gamma di modelli interessati, tra cui blueplanet 100 NX3 M8, 100 TL3 GEN2, 105 TL3 e molti altri, con versioni elencate come all/* o versioni firmware specifiche inferiori alla 6.1.4.9. KACO new energy GmbH ha rilasciato aggiornamenti per alcuni prodotti e sta preparando correzioni per altri, raccomandando contromisure dove le patch non sono ancora disponibili.

Nell'advisory non sono forniti identificatori CVE o punteggi CVSS. Le vulnerabilità sono considerate serie a causa del potenziale di sfruttamento remoto che porta ad accesso non autorizzato al dispositivo, il che potrebbe avere un impatto sull'infrastruttura dell'energia solare.

{{< netrunner-insight >}}

Per gli analisti SOC e gli ingegneri DevSecOps, questo advisory sottolinea il rischio di credenziali hardcoded o derivabili nei dispositivi IoT/OT. Inventariate immediatamente gli inverter KACO interessati e applicate gli aggiornamenti firmware dove disponibili. Per le unità non aggiornate, implementate la segmentazione di rete e monitorate i tentativi di accesso anomali come mitigazioni provvisorie.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02)**
