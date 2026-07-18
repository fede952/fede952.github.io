---
title: "La falla HollowByte di OpenSSL congela la memoria con richieste TLS da 11 byte"
date: "2026-07-18T08:44:53Z"
original_date: "2026-07-17T20:20:53"
lang: "it"
translationKey: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
slug: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
author: "NewsBot (Validated by Federico Sella)"
description: "Un bug di denial-of-service in OpenSSL, soprannominato HollowByte, consente agli attaccanti di congelare la memoria del server utilizzando piccole richieste TLS. Il Red Team di Okta lo ha segnalato; la correzione è stata rilasciata senza CVE."
original_url: "https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html"
source: "The Hacker News"
severity: "High"
target: "Server OpenSSL su sistemi glibc"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un bug di denial-of-service in OpenSSL, soprannominato HollowByte, consente agli attaccanti di congelare la memoria del server utilizzando piccole richieste TLS. Il Red Team di Okta lo ha segnalato; la correzione è stata rilasciata senza CVE.

{{< cyber-report severity="High" source="The Hacker News" target="Server OpenSSL su sistemi glibc" >}}

Una vulnerabilità di denial-ofervice recentemente divulgata in OpenSSL, denominata HollowByte dal Red Team di Okta, consente a un attaccante di esaurire la memoria del server con soli 11 byte di dati di handshake TLS. Il difetto induce un server OpenSSL non corretto ad allocare fino a 131 KB di memoria per un messaggio che non arriva mai, e sui sistemi che utilizzano glibc, quella memoria non viene liberata fino al riavvio del processo.

{{< ad-banner >}}

OpenSSL ha rilasciato la correzione nel giugno 2026 senza assegnare un identificatore CVE, pubblicare un advisory o annotare la modifica nel changelog. Il Red Team di Okta, che ha scoperto e segnalato il bug, ha pubblicato i dettagli dopo il rilascio della correzione. La vulnerabilità colpisce i server OpenSSL in esecuzione su sistemi basati su glibc, rendendoli suscettibili ad attacchi di esaurimento della memoria.

Sebbene l'attacco richieda solo un singolo ClientHello TLS di 11 byte, l'impatto può essere grave in ambienti in cui i processi OpenSSL sono longevi e gestiscono molte connessioni concorrenti. Le organizzazioni che eseguono OpenSSL su glibc dovrebbero dare priorità all'applicazione dell'aggiornamento di giugno 2026 per prevenire potenziali condizioni di denial-of-service.

{{< netrunner-insight >}}

Questo è un classico vettore di esaurimento delle risorse che bypassa il rate limiting tradizionale perché il traffico malevolo assomiglia a normali handshake TLS. Gli analisti SOC dovrebbero monitorare picchi improvvisi nell'uso della memoria sui server OpenSSL, e i team DevSecOps dovrebbero verificare che l'aggiornamento OpenSSL di giugno 2026 sia stato distribuito, anche senza un CVE. L'assenza di un CVE non riduce il rischio operativo: trattare questa patch come priorità alta.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html)**
