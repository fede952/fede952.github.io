---
title: "Nuova vulnerabilità wp2shell nel core di WordPress consente a utenti non autenticati di eseguire codice"
date: "2026-07-18T08:47:36Z"
original_date: "2026-07-17T21:20:10"
lang: "it"
translationKey: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
slug: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
author: "NewsBot (Validated by Federico Sella)"
description: "Una richiesta HTTP anonima può eseguire codice sui siti WordPress. Il bug colpisce il core, quindi anche le installazioni nude sono sfruttabili. Ogni sito 6.9 e 7.0 era a rischio fino alla patch."
original_url: "https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html"
source: "The Hacker News"
severity: "Critical"
target: "Core di WordPress (versioni 6.9 e 7.0)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una richiesta HTTP anonima può eseguire codice sui siti WordPress. Il bug colpisce il core, quindi anche le installazioni nude sono sfruttabili. Ogni sito 6.9 e 7.0 era a rischio fino alla patch.

{{< cyber-report severity="Critical" source="The Hacker News" target="Core di WordPress (versioni 6.9 e 7.0)" >}}

Una vulnerabilità critica di esecuzione remota di codice non autenticata è stata scoperta nel core di WordPress, che colpisce le versioni 6.9 e 7.0. Il difetto, soprannominato wp2shell, consente a un attaccante di eseguire codice arbitrario su un sito target inviando una richiesta HTTP appositamente predisposta. In particolare, la vulnerabilità esiste nel software core, il che significa che anche un'installazione WordPress fresca senza plugin è sfruttabile.

{{< ad-banner >}}

I dettagli tecnici completi e un proof-of-concept funzionante sono stati pubblicati, insieme agli identificatori CVE assegnati ai due difetti sottostanti. È stata anche identificata una condizione di cache oggetto persistente, che potrebbe complicare lo sfruttamento in alcuni ambienti. Tutti i siti che eseguono le versioni interessate sono stati considerati a rischio fino all'applicazione delle patch.

Si esortano gli amministratori ad aggiornare immediatamente all'ultima versione patchata. Data la facilità di sfruttamento e l'uso diffuso di WordPress, questa vulnerabilità rappresenta una minaccia significativa per la sicurezza web. Le organizzazioni dovrebbero dare priorità alla patch e rivedere le regole del firewall applicativo web per rilevare e bloccare i tentativi di sfruttamento.

{{< netrunner-insight >}}

Questo è un esempio da manuale del perché il software core deve essere indurito contro attacchi non autenticati. Gli analisti SOC dovrebbero scansionare immediatamente le istanze di WordPress 6.9 e 7.0 e verificare lo stato delle patch. I team DevSecOps dovrebbero considerarlo un promemoria per implementare la protezione runtime delle applicazioni (RASP) e monitorare richieste HTTP anomale verso wp-admin o wp-includes.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html)**
