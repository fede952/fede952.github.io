---
title: "Hacker legati alla Cina hanno backdoorato il software di login Linux per quasi un decennio"
date: "2026-06-15T13:04:59Z"
original_date: "2026-06-12T18:17:55"
lang: "it"
translationKey: "china-linked-hackers-backdoored-linux-login-software-for-nearly-a-decade"
author: "NewsBot (Validated by Federico Sella)"
description: "Un gruppo legato alla Cina noto come Velvet Ant ha compromesso i componenti PAM e OpenSSH, nascondendosi nei sistemi di login Linux per quasi dieci anni senza essere rilevato."
original_url: "https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html"
source: "The Hacker News"
severity: "High"
target: "Sistemi di login Linux (PAM, OpenSSH)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un gruppo legato alla Cina noto come Velvet Ant ha compromesso i componenti PAM e OpenSSH, nascondendosi nei sistemi di login Linux per quasi dieci anni senza essere rilevato.

{{< cyber-report severity="High" source="The Hacker News" target="Sistemi di login Linux (PAM, OpenSSH)" >}}

Un attore di minaccia legato alla Cina, tracciato come Velvet Ant, è stato scoperto aver backdoorato componenti fondamentali del login Linux, inclusi PAM (Pluggable Authentication Modules) e OpenSSH, permettendo loro di mantenere un accesso persistente per quasi un decennio. Il gruppo ha preso di mira una rete in cui hanno inserito la loro backdoor in profondità nello stack di autenticazione, rendendola resistente alle procedure di pulizia standard.

{{< ad-banner >}}

Secondo la società di sicurezza Sygnia, gli aggressori hanno sfruttato la fiducia riposta nel software di login per eludere il rilevamento. Modificando i meccanismi stessi che controllano l'accesso degli utenti, hanno garantito che il loro punto d'appoggio sopravvivesse agli aggiornamenti di sistema e alle scansioni di sicurezza di routine. La campagna evidenzia la crescente sofisticazione dei gruppi sponsorizzati da stati nel prendere di mira le infrastrutture fondamentali.

La compromissione sottolinea la necessità per le organizzazioni di monitorare l'integrità dei componenti critici del sistema oltre il rilevamento tipico degli endpoint. I difensori dovrebbero considerare il monitoraggio dell'integrità dei file per i moduli PAM e i binari SSH, nonché l'analisi comportamentale dei log di autenticazione per individuare anomalie indicative di processi di login backdoorati.

{{< netrunner-insight >}}

Per gli analisti SOC e i team DevSecOps, questo è un duro promemoria che gli aggressori stanno prendendo di mira il livello di autenticazione stesso. Implementate controlli di integrità in esecuzione sui binari PAM e OpenSSH e considerate l'uso del monitoraggio a livello di kernel per rilevare manomissioni. Inoltre, rivedete le modifiche all'autenticazione basata su chiave SSH e alla configurazione PAM come parte dei vostri playbook di risposta agli incidenti.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html)**
