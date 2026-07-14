---
title: "Fuga di dati su GitHub della CISA espone chiavi AWS GovCloud per sei mesi"
date: "2026-07-14T09:01:14Z"
original_date: "2026-07-13T15:03:28"
lang: "it"
translationKey: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
slug: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
author: "NewsBot (Validated by Federico Sella)"
description: "Un appaltatore ha divulgato accidentalmente credenziali interne della CISA, incluse chiavi AWS GovCloud, su GitHub per sei mesi. Gli esperti evidenziano lezioni critiche per i team di sicurezza."
original_url: "https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/"
source: "Krebs on Security"
severity: "High"
target: "repository GitHub della CISA"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un appaltatore ha divulgato accidentalmente credenziali interne della CISA, incluse chiavi AWS GovCloud, su GitHub per sei mesi. Gli esperti evidenziano lezioni critiche per i team di sicurezza.

{{< cyber-report severity="High" source="Krebs on Security" target="repository GitHub della CISA" >}}

La Cybersecurity and Infrastructure Security Agency (CISA) ha rivelato una fuga di dati in cui un appaltatore ha pubblicato involontariamente dozzine di credenziali interne, incluse chiavi AWS GovCloud, in un repository pubblico su GitHub. Le credenziali sono rimaste esposte per quasi sei mesi prima che KrebsOnSecurity avvisasse l'agenzia.

{{< ad-banner >}}

L'analisi post-mortem della CISA ha identificato lacune nella risposta iniziale, come la rilevazione ritardata e la mancanza di scansione automatica dei segreti nei repository pubblici. L'incidente sottolinea la necessità di una gestione robusta dei segreti e di un monitoraggio continuo dei repository di codice.

Gli esperti raccomandano l'implementazione di pre-commit hook, scansione regolare dei segreti e controlli di accesso rigorosi per prevenire fughe simili. L'uso di credenziali effimere e la rotazione automatica possono anche mitigare l'impatto delle chiavi esposte.

{{< netrunner-insight >}}

Questo incidente è un caso da manuale del perché la scansione dei segreti deve essere integrata nelle pipeline CI/CD, non solo dopo il commit. Gli analisti SOC dovrebbero dare priorità agli avvisi per esposizioni su repository pubblici, e i team DevSecOps dovrebbero imporre l'accesso con privilegi minimi per gli appaltatori. Automatizzare la rotazione delle credenziali e considerare l'uso di strumenti come GitLeaks o TruffleHog per individuare precocemente le fughe.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su Krebs on Security ›](https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/)**
