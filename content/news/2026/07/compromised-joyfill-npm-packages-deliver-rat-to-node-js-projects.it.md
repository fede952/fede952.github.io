---
title: "Pacchetti npm joyfill compromessi distribuiscono RAT a progetti Node.js"
date: "2026-07-29T09:34:53Z"
original_date: "2026-07-29T04:20:57"
lang: "it"
translationKey: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
slug: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
author: "NewsBot (Validated by Federico Sella)"
description: "Le versioni beta di @joyfill/layouts e @joyfill/components contengono un impianto JavaScript al momento dell'importazione che risolve codice crittografato per distribuire un trojan ad accesso remoto."
original_url: "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "Sviluppatori Node.js che utilizzano pacchetti joyfill"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Le versioni beta di @joyfill/layouts e @joyfill/components contengono un impianto JavaScript al momento dell'importazione che risolve codice crittografato per distribuire un trojan ad accesso remoto.

{{< cyber-report severity="High" source="The Hacker News" target="Sviluppatori Node.js che utilizzano pacchetti joyfill" >}}

Due pacchetti npm nel namespace @joyfill, @joyfill/layouts versione 0.1.2-2773.beta.0 e @joyfill/components versione 4.0.0-rc24-2773-beta.4, sono stati compromessi. Queste versioni beta contengono un impianto JavaScript al momento dell'importazione che risolve codice crittografato, distribuendo infine un trojan ad accesso remoto (RAT) associato alla famiglia di malware DEV#POPPER.

{{< ad-banner >}}

Il codice malevolo viene eseguito quando i pacchetti vengono importati in un progetto Node.js, dando agli attaccanti accesso remoto al sistema compromesso. L'attacco evidenzia il rischio continuo di attacchi alla supply chain che prendono di mira l'ecosistema npm, in particolare attraverso versioni beta o release candidate che potrebbero ricevere meno controlli.

Gli sviluppatori che hanno utilizzato queste versioni specifiche dovrebbero immediatamente ruotare le credenziali, scansionare per indicatori di compromissione e rivedere i propri alberi delle dipendenze per qualsiasi altro pacchetto sospetto. Il registro npm ha probabilmente rimosso le versioni malevole, ma le installazioni esistenti rimangono una minaccia.

{{< netrunner-insight >}}

Questo incidente sottolinea l'importanza di esaminare i pacchetti pre-release e implementare controlli di integrità delle dipendenze. Gli analisti SOC dovrebbero monitorare connessioni in uscita anomale dalle applicazioni Node.js, mentre i team DevSecOps dovrebbero imporre un versionamento rigoroso e utilizzare strumenti come npm audit o scanner SCA per rilevare pacchetti malevoli noti.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html)**
