---
title: "Pacchetti npm dannosi mascherati da strumenti PostCSS distribuiscono RAT per Windows"
date: "2026-06-23T10:35:14Z"
original_date: "2026-06-23T08:54:32"
lang: "it"
translationKey: "malicious-npm-packages-disguised-as-postcss-tools-deliver-windows-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Tre pacchetti npm dannosi che si spacciano per strumenti PostCSS sono stati scoperti mentre distribuivano un trojan ad accesso remoto per Windows. I ricercatori invitano alla cautela durante l'installazione di pacchetti npm."
original_url: "https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html"
source: "The Hacker News"
severity: "High"
target: "utenti npm, sistemi Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Tre pacchetti npm dannosi che si spacciano per strumenti PostCSS sono stati scoperti mentre distribuivano un trojan ad accesso remoto per Windows. I ricercatori invitano alla cautela durante l'installazione di pacchetti npm.

{{< cyber-report severity="High" source="The Hacker News" target="utenti npm, sistemi Windows" >}}

I ricercatori di cybersecurity hanno identificato tre pacchetti npm dannosi—aes-decode-runner-pro, postcss-minify-selector e postcss-minify-selector-parser—progettati per distribuire un trojan ad accesso remoto (RAT) per Windows. I pacchetti sono stati pubblicati nell'ultimo mese da un utente npm e hanno accumulato un totale di 1.016 download, indicando una distribuzione moderata ma preoccupante.

{{< ad-banner >}}

I pacchetti si mascherano da strumenti legittimi di PostCSS, un popolare post-processore CSS, per indurre gli sviluppatori a installarli. Una volta installati, il codice dannoso esegue un payload che stabilisce un accesso remoto al computer Windows infetto, consentendo potenzialmente agli aggressori di esfiltrare dati, installare malware aggiuntivo o muoversi lateralmente nella rete.

Questo incidente evidenzia la minaccia continua del typosquatting e della confusione delle dipendenze nell'ecosistema npm. Si consiglia agli sviluppatori di verificare attentamente i nomi dei pacchetti, rivedere il codice sorgente prima dell'installazione e utilizzare strumenti di verifica dell'integrità dei pacchetti per mitigare tali rischi.

{{< netrunner-insight >}}

Per gli analisti SOC e gli ingegneri DevSecOps, questo è un promemoria per imporre controlli rigorosi sulla provenienza dei pacchetti e monitorare installazioni anomale di pacchetti npm. Considerare l'implementazione di scansioni automatiche per pacchetti dannosi noti e formare gli sviluppatori sui rischi di fidarsi ciecamente dei nomi dei pacchetti. Il numero relativamente basso di download suggerisce che questa campagna potrebbe essere in fase iniziale, quindi è opportuna una caccia proattiva a pacchetti simili.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html)**
