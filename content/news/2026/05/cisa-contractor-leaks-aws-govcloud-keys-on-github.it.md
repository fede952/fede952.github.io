---
title: "Appaltatore CISA Espone Chiavi AWS GovCloud su GitHub"
date: "2026-05-19T10:35:27Z"
original_date: "2026-05-18T20:48:21"
lang: "it"
translationKey: "cisa-contractor-leaks-aws-govcloud-keys-on-github"
author: "NewsBot (Validated by Federico Sella)"
description: "Un appaltatore della CISA ha esposto credenziali AWS GovCloud e dettagli interni di build in un repository pubblico su GitHub, segnando una delle più gravi fughe di dati governativi."
original_url: "https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/"
source: "Krebs on Security"
severity: "Critical"
target: "account AWS GovCloud della CISA"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un appaltatore della CISA ha esposto credenziali AWS GovCloud e dettagli interni di build in un repository pubblico su GitHub, segnando una delle più gravi fughe di dati governativi.

{{< cyber-report severity="Critical" source="Krebs on Security" target="account AWS GovCloud della CISA" >}}

Fino allo scorso fine settimana, un appaltatore della Cybersecurity & Infrastructure Security Agency (CISA) ha mantenuto un repository pubblico su GitHub che esponeva credenziali per diversi account AWS GovCloud altamente privilegiati e un gran numero di sistemi interni della CISA. Gli esperti di sicurezza hanno affermato che l'archivio pubblico includeva file che descrivono come la CISA costruisce, testa e distribuisce software internamente, e che rappresenta una delle più gravi fughe di dati governative della storia recente.

{{< ad-banner >}}

Le credenziali esposte potrebbero consentire a un attaccante di accedere ad ambienti cloud governativi sensibili e sistemi interni, portando potenzialmente all'esfiltrazione di dati o a ulteriori compromissioni. L'incidente sottolinea i rischi dei segreti hardcoded nei repository pubblici, anche da parte di appaltatori governativi.

{{< netrunner-insight >}}

Questa fuga di dati evidenzia la necessità critica di scansione automatica dei segreti e controlli rigorosi sull'accesso ai repository. Gli analisti SOC dovrebbero dare priorità al monitoraggio delle credenziali esposte nei repository di codice pubblico, mentre i team DevSecOps devono applicare politiche di gestione dei segreti e ruotare immediatamente qualsiasi chiave potenzialmente compromessa.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su Krebs on Security ›](https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/)**
