---
title: "UAC-0145 collegato a Sandworm usa finte interviste di lavoro per diffondere una VPN dannosa"
date: "2026-08-15T07:23:49Z"
original_date: "2026-08-11T18:36:47"
lang: "it"
translationKey: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
slug: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
author: "NewsBot (Validated by Federico Sella)"
description: "Il CERT-UA mette in guardia da attori di minaccia legati allo stato russo che prendono di mira i lavoratori IT ucraini tramite finte interviste di lavoro, consegnando una VPN in grado di eseguire comandi."
original_url: "https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html"
source: "The Hacker News"
severity: "High"
target: "Lavoratori IT ucraini"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Il CERT-UA mette in guardia da attori di minaccia legati allo stato russo che prendono di mira i lavoratori IT ucraini tramite finte interviste di lavoro, consegnando una VPN in grado di eseguire comandi.

{{< cyber-report severity="High" source="The Hacker News" target="Lavoratori IT ucraini" >}}

Il CERT-UA ha reso nota una nuova campagna di ingegneria sociale attribuita al cluster di minaccia UAC-0145, un sottogruppo del gruppo statale russo Sandworm (APT44). La campagna prende di mira i lavoratori IT in Ucraina impersonando reclutatori e attirando le vittime in finte interviste di lavoro.

{{< ad-banner >}}

Durante il processo di intervista, le vittime vengono indotte a installare un'applicazione VPN che in realtà è un malware in grado di eseguire comandi arbitrari sul sistema compromesso. Questa tecnica sfrutta la fiducia associata al reclutamento lavorativo per aggirare le difese degli utenti.

L'attività sottolinea la minaccia informatica in corso da parte di attori sponsorizzati dallo stato russo contro le organizzazioni ucraine, in particolare quelle del settore IT. L'attribuzione del CERT-UA a UAC-0145 evidenzia la natura sofisticata e persistente di questi attacchi.

{{< netrunner-insight >}}

Questa campagna dimostra l'efficacia dell'ingegneria sociale nel distribuire malware, anche a professionisti IT attenti alla sicurezza. Gli analisti SOC dovrebbero educare gli utenti su tali esche basate sul reclutamento e monitorare installazioni VPN insolite o esecuzioni di comandi. I team DevSecOps dovrebbero applicare liste bianche delle applicazioni e limitare l'esecuzione di binari non firmati per mitigare tali minacce.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html)**
