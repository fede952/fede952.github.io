---
title: "La falla Ill Bloom prosciuga 3,1 milioni di dollari dai portafogli crypto tramite frasi di recupero deboli"
date: "2026-07-10T10:19:16Z"
original_date: "2026-07-10T09:00:05"
lang: "it"
translationKey: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
slug: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
author: "NewsBot (Validated by Federico Sella)"
description: "Gli attaccanti sfruttano una vulnerabilità nella generazione delle frasi di recupero dei portafogli di criptovalute, chiamata Ill Bloom, per rubare 3,1 milioni di dollari in un'operazione coordinata."
original_url: "https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html"
source: "The Hacker News"
severity: "High"
target: "portafogli di criptovalute"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Gli attaccanti sfruttano una vulnerabilità nella generazione delle frasi di recupero dei portafogli di criptovalute, chiamata Ill Bloom, per rubare 3,1 milioni di dollari in un'operazione coordinata.

{{< cyber-report severity="High" source="The Hacker News" target="portafogli di criptovalute" >}}

La società di sicurezza Coinspect ha divulgato una vulnerabilità nel software dei portafogli di criptovalute, denominata Ill Bloom, che consente agli attaccanti di prosciugare i fondi sfruttando una debole casualità nella generazione delle frasi di recupero. La falla riguarda il modo in cui alcuni portafogli creano la frase mnemonica che controlla l'accesso ai fondi del portafoglio. Quando la casualità è insufficiente, un attaccante può calcolare la frase e ottenere il controllo completo del portafoglio.

{{< ad-banner >}}

Coinspect ha confermato che gli attaccanti hanno già sfruttato questa vulnerabilità in un'operazione coordinata a maggio, rubando circa 3,1 milioni di dollari da diversi portafogli. La data esatta e la portata completa dell'attacco non sono state divulgate, ma l'incidente evidenzia l'importanza critica della generazione sicura di numeri casuali nelle applicazioni crittografiche.

Si consiglia agli utenti di portafogli di verificare che il proprio software utilizzi generatori di numeri casuali crittograficamente sicuri e di considerare il trasferimento dei fondi verso portafogli con implementazioni di casualità sottoposte a audit. Gli sviluppatori dovrebbero rivedere le proprie fonti di entropia e garantire la conformità con standard di settore come BIP39.

{{< netrunner-insight >}}

Questo incidente sottolinea il pericolo di fare affidamento su entropia debole nella generazione di chiavi crittografiche. Gli analisti SOC dovrebbero monitorare transazioni anomale dei portafogli o movimenti di massa di fondi, mentre gli ingegneri DevSecOps devono verificare tutta la generazione di numeri casuali nelle applicazioni critiche per la sicurezza. Supponete sempre che la casualità prevedibile verrà sfruttata.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html)**
