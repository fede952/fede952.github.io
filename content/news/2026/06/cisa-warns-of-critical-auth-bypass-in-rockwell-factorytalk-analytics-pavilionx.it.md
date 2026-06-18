---
title: "CISA avverte di un bypass critico dell'autenticazione in Rockwell FactoryTalk Analytics PavilionX"
date: "2026-06-18T11:06:01Z"
original_date: "2026-06-16T12:00:00"
lang: "it"
translationKey: "cisa-warns-of-critical-auth-bypass-in-rockwell-factorytalk-analytics-pavilionx"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA segnala CVE-2025-14272 che colpisce Rockwell Automation FactoryTalk Analytics PavilionX <7.01, consentendo operazioni privilegiate non autorizzate in ambienti di produzione critici."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01"
source: "CISA"
severity: "High"
target: "Rockwell FactoryTalk Analytics PavilionX"
cve: "CVE-2025-14272"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA segnala CVE-2025-14272 che colpisce Rockwell Automation FactoryTalk Analytics PavilionX <7.01, consentendo operazioni privilegiate non autorizzate in ambienti di produzione critici.

{{< cyber-report severity="High" source="CISA" target="Rockwell FactoryTalk Analytics PavilionX" cve="CVE-2025-14272" >}}

CISA ha pubblicato un avviso (ICSA-26-167-01) riguardante una vulnerabilità di autorizzazione mancante in Rockwell Automation FactoryTalk Analytics PavilionX. Il difetto, tracciato come CVE-2025-14272, colpisce le versioni precedenti alla 7.01 e consente a un utente malintenzionato non autorizzato di eseguire operazioni privilegiate come la gestione di utenti e ruoli.

{{< ad-banner >}}

La vulnerabilità deriva da un'applicazione impropria delle autorizzazioni negli endpoint API. Lo sfruttamento riuscito potrebbe portare al controllo amministrativo completo del sistema interessato. Rockwell Automation ha rilasciato la versione 7.01 per risolvere il problema e si esorta gli utenti ad aggiornare immediatamente.

Considerando la diffusione di questo prodotto in settori manifatturieri critici a livello mondiale, il rischio di interruzione operativa o compromissione dei dati è significativo. Le organizzazioni dovrebbero dare priorità alla correzione e rivedere i controlli di accesso per mitigare potenziali sfruttamenti.

{{< netrunner-insight >}}

Questo è un classico bypass di autorizzazione che dovrebbe essere trattato come una patch ad alta priorità. Gli analisti SOC dovrebbero monitorare chiamate API anomale o escalation di privilegi negli ambienti PavilionX. I team DevSecOps devono assicurarsi che la versione 7.01 sia distribuita e che la segmentazione di rete limiti l'esposizione di questi endpoint.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01)**
