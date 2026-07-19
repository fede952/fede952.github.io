---
title: "La vulnerabilità DDoS HollowByte gonfia la memoria dei server OpenSSL con un payload di 11 byte"
date: "2026-07-19T09:04:58Z"
original_date: "2026-07-17T17:56:21"
lang: "it"
translationKey: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
slug: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
author: "NewsBot (Validated by Federico Sella)"
description: "Una vulnerabilità denominata HollowByte consente ad attaccanti non autenticati di causare una condizione di denial-of-service sui server OpenSSL con un payload malevolo di soli 11 byte."
original_url: "https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/"
source: "BleepingComputer"
severity: "High"
target: "Server OpenSSL"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una vulnerabilità denominata HollowByte consente ad attaccanti non autenticati di causare una condizione di denial-of-service sui server OpenSSL con un payload malevolo di soli 11 byte.

{{< cyber-report severity="High" source="BleepingComputer" target="Server OpenSSL" >}}

Una vulnerabilità appena scoperta, chiamata HollowByte, consente ad attaccanti non autenticati di causare una condizione di denial-of-service (DoS) sui server OpenSSL inviando un payload appositamente predisposto di soli 11 byte. Il difetto sfrutta inefficienze nell'allocazione della memoria, facendo gonfiare la memoria del server fino a esaurire le risorse disponibili.

{{< ad-banner >}}

L'attacco non richiede autenticazione e può essere eseguito da remoto, rappresentando una minaccia significativa per qualsiasi organizzazione che si affida a OpenSSL per comunicazioni sicure. La dimensione minima del payload consente agli attaccanti di amplificare il loro impatto con larghezza di banda limitata, potenzialmente sovraccaricando i server con il minimo sforzo.

Sebbene non sia stato ancora assegnato un identificatore CVE, la vulnerabilità è stata divulgata al progetto OpenSSL e sono previste patch. Nel frattempo, si consiglia agli amministratori di monitorare l'uso della memoria e implementare limitazioni di velocità o regole di rilevamento delle intrusioni per mitigare potenziali sfruttamenti.

{{< netrunner-insight >}}

Per gli analisti SOC, questo è un classico vettore DoS a bassa larghezza di banda e alto impatto che può bypassare le difese volumetriche tradizionali. I team DevSecOps dovrebbero dare priorità all'applicazione delle patch non appena disponibili e considerare l'implementazione di avvisi di monitoraggio della memoria per rilevare una crescita anomala. Il payload di 11 byte lo rende un candidato ideale per l'inclusione nelle regole di rilevamento delle minacce.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/)**
