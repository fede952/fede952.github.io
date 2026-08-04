---
title: "Pacchetti npm dannosi prendono di mira gli utenti degli strumenti Alibaba con un RAT multipiattaforma"
date: "2026-08-04T09:40:19Z"
original_date: "2026-08-03T18:43:53"
lang: "it"
translationKey: "malicious-npm-packages-target-alibaba-tool-users-with-cross-platform-rat"
slug: "malicious-npm-packages-target-alibaba-tool-users-with-cross-platform-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "I ricercatori scoprono 18 pacchetti npm dannosi, incluso 'lib-mtop', che distribuiscono un RAT multipiattaforma agli utenti degli strumenti di sviluppo Alibaba in un attacco mirato alla supply chain."
original_url: "https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html"
source: "The Hacker News"
severity: "High"
target: "Utenti degli strumenti di sviluppo Alibaba"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

I ricercatori scoprono 18 pacchetti npm dannosi, incluso 'lib-mtop', che distribuiscono un RAT multipiattaforma agli utenti degli strumenti di sviluppo Alibaba in un attacco mirato alla supply chain.

{{< cyber-report severity="High" source="The Hacker News" target="Utenti degli strumenti di sviluppo Alibaba" >}}

I ricercatori di cybersecurity hanno identificato un nuovo set di 18 pacchetti npm dannosi progettati per prendere di mira gli utenti degli strumenti di sviluppo Alibaba. L'attacco fa parte di una campagna sofisticata e mirata alla supply chain software che si concentra specificamente su ambienti di lingua cinese, indicando un alto livello di ricognizione e localizzazione.

{{< ad-banner >}}

Uno dei pacchetti, 'lib-mtop', è un pacchetto non scoped che condivide lo stesso nome di un pacchetto privato Alibaba, una classica tecnica di typosquatting. Ciò suggerisce che gli attaccanti stiano tentando di ingannare gli sviluppatori che potrebbero installare erroneamente il pacchetto dannoso invece di quello legittimo, ottenendo così un punto d'appoggio nei loro ambienti di sviluppo.

I pacchetti dannosi distribuiscono un trojan di accesso remoto (RAT) multipiattaforma alle vittime, che può fornire agli attaccanti il controllo remoto sui sistemi compromessi. La natura multipiattaforma del RAT indica che è progettato per colpire un'ampia gamma di sistemi operativi, aumentando il potenziale impatto dell'attacco.

{{< netrunner-insight >}}

Questo attacco sottolinea l'importanza di verificare l'autenticità dei pacchetti, specialmente quando si utilizzano pacchetti privati o interni. Gli analisti SOC e gli ingegneri DevSecOps dovrebbero implementare controlli rigorosi sulla provenienza dei pacchetti, come l'uso di file di blocco e la verifica dell'integrità dei pacchetti, e monitorare connessioni di rete inattese dalle macchine di sviluppo. Inoltre, considerare l'uso di un registro privato con liste consentite per prevenire attacchi di typosquatting.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html)**
