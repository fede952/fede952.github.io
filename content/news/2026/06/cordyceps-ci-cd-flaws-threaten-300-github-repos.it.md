---
title: "Vulnerabilità CI/CD Cordyceps minacciano oltre 300 repository GitHub"
date: "2026-06-25T10:14:17Z"
original_date: "2026-06-24T12:48:11"
lang: "it"
translationKey: "cordyceps-ci-cd-flaws-threaten-300-github-repos"
author: "NewsBot (Validated by Federico Sella)"
description: "Una nuova debolezza nei workflow CI/CD, soprannominata Cordyceps, consente agli attaccanti di dirottare i workflow e compromettere le catene di approvvigionamento open-source di grandi organizzazioni."
original_url: "https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html"
source: "The Hacker News"
severity: "Critical"
target: "workflow CI/CD su GitHub"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una nuova debolezza nei workflow CI/CD, soprannominata Cordyceps, consente agli attaccanti di dirottare i workflow e compromettere le catene di approvvigionamento open-source di grandi organizzazioni.

{{< cyber-report severity="Critical" source="The Hacker News" target="workflow CI/CD su GitHub" >}}

I ricercatori di cybersecurity di Novee Security hanno identificato un pattern critico sfruttabile nei workflow CI/CD, denominato Cordyceps, che può consentire agli attaccanti di dirottare i workflow e compromettere le catene di approvvigionamento open-source. La vulnerabilità interessa oltre 300 repository GitHub appartenenti a grandi organizzazioni tra cui Microsoft, Google e Apache.

{{< ad-banner >}}

Il pattern Cordyceps permette il controllo completo dei repository da parte degli attaccanti, portando potenzialmente a modifiche non autorizzate del codice, inserimento di backdoor e attacchi a valle alla catena di approvvigionamento. La vulnerabilità deriva da configurazioni di workflow insicure che non isolano o convalidano adeguatamente gli input.

Si esortano le organizzazioni che utilizzano GitHub Actions o piattaforme CI/CD simili a rivedere le definizioni dei propri workflow per il pattern Cordyceps e implementare permessi con privilegi minimi, sanificazione degli input e isolamento dell'ambiente per mitigare il rischio.

{{< netrunner-insight >}}

Questo è un classico vettore di attacco alla catena di approvvigionamento. Gli analisti SOC dovrebbero monitorare esecuzioni anomale dei workflow e modifiche inaspettate ai repository. I team DevSecOps devono controllare immediatamente le configurazioni delle pipeline CI/CD, concentrandosi sulla gestione degli input non fidati e sull'ambito dei permessi.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)**
