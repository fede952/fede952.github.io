---
title: "LastPass conferma violazione dei dati tramite attacco alla supply chain di Klue"
date: "2026-06-24T10:23:36Z"
original_date: "2026-06-23T13:58:25"
lang: "it"
translationKey: "lastpass-confirms-data-breach-via-klue-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "LastPass ha rivelato che gli aggressori hanno rubato token OAuth da un'applicazione di terze parti, Klue, per accedere ai dati dei clienti nel suo ambiente Salesforce."
original_url: "https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Ambiente Salesforce di LastPass"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

LastPass ha rivelato che gli aggressori hanno rubato token OAuth da un'applicazione di terze parti, Klue, per accedere ai dati dei clienti nel suo ambiente Salesforce.

{{< cyber-report severity="High" source="BleepingComputer" target="Ambiente Salesforce di LastPass" >}}

LastPass ha confermato che gli hacker hanno avuto accesso ai dati dei clienti dal suo ambiente Salesforce dopo aver rubato i token OAuth dell'azienda nell'attacco alla supply chain di Klue all'inizio di questo mese. La violazione, resa nota il 23 giugno 2026, evidenzia i rischi delle integrazioni di terze parti e del furto di token.

{{< ad-banner >}}

Gli aggressori hanno utilizzato token OAuth compromessi di Klue, un'applicazione di terze parti, per ottenere accesso non autorizzato all'istanza Salesforce di LastPass. Questo attacco alla supply chain ha permesso agli attori delle minacce di esfiltrare dati dei clienti senza attivare i normali avvisi di autenticazione.

LastPass sta notificando i clienti interessati e ha revocato i token compromessi. L'azienda sta anche rivedendo le proprie politiche di accesso di terze parti per prevenire incidenti simili. Questa violazione sottolinea l'importanza di monitorare l'uso dei token OAuth e di implementare controlli di accesso rigorosi per i servizi integrati.

{{< netrunner-insight >}}

Questo incidente è un esempio da manuale di rischio nella supply chain tramite abuso di token OAuth. Gli analisti SOC dovrebbero dare priorità al monitoraggio dell'uso anomalo dei token e implementare politiche di scadenza dei token. I team DevSecOps devono applicare il principio del minimo privilegio per le integrazioni di terze parti e considerare l'uso di token a breve durata per ridurre il raggio d'esplosione.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/)**
