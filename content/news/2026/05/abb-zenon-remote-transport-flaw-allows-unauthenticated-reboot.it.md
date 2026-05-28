---
title: "Difetto di trasporto remoto in ABB Zenon consente riavvio non autorizzato"
date: "2026-05-28T10:50:49Z"
original_date: "2026-05-26T12:00:00"
lang: "it"
translationKey: "abb-zenon-remote-transport-flaw-allows-unauthenticated-reboot"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA avverte di CVE-2025-8754 in ABB Ability Zenon, che consente riavvii non autorizzati del sistema tramite il servizio di trasporto remoto. Nessuna sfruttamento attivo segnalato."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03"
source: "CISA"
severity: "High"
target: "Sistemi ABB Ability Zenon"
cve: "CVE-2025-8754"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA avverte di CVE-2025-8754 in ABB Ability Zenon, che consente riavvii non autorizzati del sistema tramite il servizio di trasporto remoto. Nessuna sfruttamento attivo segnalato.

{{< cyber-report severity="High" source="CISA" target="Sistemi ABB Ability Zenon" cve="CVE-2025-8754" cvss="7.5" >}}

CISA ha pubblicato un advisory (ICSA-26-146-03) che descrive una vulnerabilità di autenticazione mancante nel servizio di trasporto remoto di ABB Ability Zenon. La falla, tracciata come CVE-2025-8754 con un punteggio CVSS di 7.5, consente a un attaccante di attivare un riavvio del sistema senza credenziali adeguate. Le versioni interessate vanno dalla 7.50 alla 14.

{{< ad-banner >}}

Lo sfruttamento richiede un accesso di rete preliminare, poiché l'attaccante deve già trovarsi sulla stessa rete del sistema Zenon target. ABB nota che nelle configurazioni predefinite, il servizio zensyssrv.exe si avvia automaticamente, ma gli utenti devono configurare una password per utilizzare il servizio di trasporto remoto. Al momento della scrittura, non ci sono prove di sfruttamento attivo in natura.

L'advisory evidenzia l'ampia diffusione di ABB Ability Zenon in settori di infrastrutture critiche tra cui Chimico, Energia, Sanità e Sistemi idrici e di acque reflue in tutto il mondo. Le organizzazioni che utilizzano versioni interessate dovrebbero applicare immediatamente le mitigazioni o gli aggiornamenti forniti da ABB per prevenire potenziali attacchi denial-of-service.

{{< netrunner-insight >}}

Per gli analisti SOC: dare priorità alla segmentazione di rete per limitare l'esposizione dei sistemi Zenon e assicurarsi che le password del servizio di trasporto remoto siano configurate e robuste. I team DevSecOps dovrebbero verificare che il servizio zensyssrv.exe non sia esposto a reti non fidate e applicare le patch del fornitore non appena disponibili. Dato il CVSS 7.5 e l'impatto sulle infrastrutture critiche, trattare questa come una scoperta ad alta priorità anche senza sfruttamento attivo.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03)**
