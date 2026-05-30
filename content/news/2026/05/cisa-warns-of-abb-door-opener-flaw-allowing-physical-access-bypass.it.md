---
title: "CISA avverte di una falla nel citofono ABB che consente l'elusione dell'accesso fisico"
date: "2026-05-30T09:11:24Z"
original_date: "2026-05-28T12:00:00"
lang: "it"
translationKey: "cisa-warns-of-abb-door-opener-flaw-allowing-physical-access-bypass"
author: "NewsBot (Validated by Federico Sella)"
description: "L'avviso CISA ICSA-26-148-04 descrive una vulnerabilità di bypass dell'autenticazione (CVE-2025-7705) nell'attuatore per citofono ABB Busch-Welcome 2 Wire Door Opener, che consente l'accesso non autorizzato agli edifici."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04"
source: "CISA"
severity: "Medium"
target: "ABB Busch-Welcome 2 Wire Door Opener Actuator"
cve: "CVE-2025-7705"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

L'avviso CISA ICSA-26-148-04 descrive una vulnerabilità di bypass dell'autenticazione (CVE-2025-7705) nell'attuatore per citofono ABB Busch-Welcome 2 Wire Door Opener, che consente l'accesso non autorizzato agli edifici.

{{< cyber-report severity="Medium" source="CISA" target="ABB Busch-Welcome 2 Wire Door Opener Actuator" cve="CVE-2025-7705" cvss="6.8" >}}

CISA ha pubblicato l'avviso ICSA-26-148-04 riguardante una vulnerabilità di bypass dell'autenticazione nell'attuatore per citofono ABB Busch-Welcome 2 Wire Door Opener, identificata come CVE-2025-7705. La falla deriva da una modalità di compatibilità abilitata per impostazione predefinita, che consente a un aggressore di ottenere accesso fisico non autorizzato agli edifici in cui è installato il prodotto interessato. La vulnerabilità interessa tutte le versioni di Switch Actuator 4 DU e Switch actuator, door/light 4 DU.

{{< ad-banner >}}

Il punteggio base CVSS v3 per questa vulnerabilità è 6.8, indicando una gravità media. ABB ha fornito misure di remediation che prevedono di commutare l'interruttore di modalità sul prodotto e di eseguire un reset di alimentazione per ricalibrare il sistema. Il prodotto è distribuito in tutto il mondo, principalmente in strutture commerciali, e il produttore ha sede in Svizzera.

Le organizzazioni che utilizzano i sistemi ABB Busch-Welcome interessati dovrebbero applicare immediatamente le mitigazioni raccomandate. Date le implicazioni per la sicurezza fisica, questa vulnerabilità rappresenta un rischio significativo per il controllo degli accessi agli edifici. I team di sicurezza dovrebbero verificare che le fasi di ricalibrazione siano eseguite correttamente e monitorare eventuali segni di sfruttamento.

{{< netrunner-insight >}}

Questa vulnerabilità è un duro promemoria del fatto che i dispositivi IoT e di automazione degli edifici spesso vengono forniti con impostazioni predefinite insicure. Gli analisti SOC dovrebbero dare priorità alla scoperta delle risorse per i sistemi ABB Busch-Welcome e assicurarsi che la ricalibrazione manuale venga applicata. I team DevSecOps devono sostenere i principi di progettazione sicura, specialmente per i dispositivi che controllano l'accesso fisico.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04)**
