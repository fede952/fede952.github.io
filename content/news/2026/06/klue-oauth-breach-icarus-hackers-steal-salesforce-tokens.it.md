---
title: "Violazione OAuth di Klue: gli hacker Icarus rubano token Salesforce"
date: "2026-06-20T09:59:52Z"
original_date: "2026-06-19T22:31:04"
lang: "it"
translationKey: "klue-oauth-breach-icarus-hackers-steal-salesforce-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Klue conferma il furto di token OAuth che ha impattato le integrazioni Salesforce; il gruppo di estorsione Icarus rivendica la responsabilità e la lista delle vittime si allunga."
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/"
source: "BleepingComputer"
severity: "High"
target: "piattaforma di market intelligence Klue"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Klue conferma il furto di token OAuth che ha impattato le integrazioni Salesforce; il gruppo di estorsione Icarus rivendica la responsabilità e la lista delle vittime si allunga.

{{< cyber-report severity="High" source="BleepingComputer" target="piattaforma di market intelligence Klue" >}}

La piattaforma di market intelligence Klue ha confermato un incidente di sicurezza in cui attori malevoli hanno rubato token OAuth utilizzati per connettersi agli ambienti Salesforce dei clienti. La violazione, rivendicata dal gruppo di estorsione 'Icarus' recentemente emerso, ha portato a un elenco crescente di vittime colpite.

{{< ad-banner >}}

I token OAuth rubati potrebbero consentire agli aggressori di accedere ai dati di Salesforce senza necessitare di ulteriore autenticazione, rappresentando un rischio significativo per i clienti di Klue. L'incidente evidenzia i pericoli dell'esposizione dei token OAuth e la necessità di una gestione robusta del ciclo di vita dei token.

Mentre il gruppo Icarus rivendica pubblicamente l'attacco, le organizzazioni che utilizzano l'integrazione Salesforce di Klue dovrebbero revocare e ruotare immediatamente qualsiasi token OAuth associato e monitorare eventuali accessi non autorizzati. L'intera portata della violazione è ancora sotto indagine.

{{< netrunner-insight >}}

Questo incidente sottolinea l'importanza critica di proteggere i token OAuth come credenziali sensibili. Gli analisti SOC dovrebbero dare priorità al monitoraggio di chiamate API Salesforce anomale e applicare politiche di scadenza dei token. I team DevSecOps devono implementare meccanismi rigorosi di scoping e rotazione dei token per limitare il raggio d'esplosione in caso di compromissione.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/)**
