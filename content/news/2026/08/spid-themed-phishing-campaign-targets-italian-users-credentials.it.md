---
title: "Campagna di phishing a tema SPID mira alle credenziali degli utenti italiani"
date: "2026-08-17T07:50:54Z"
original_date: "2026-08-03T11:05:05"
lang: "it"
translationKey: "spid-themed-phishing-campaign-targets-italian-users-credentials"
slug: "spid-themed-phishing-campaign-targets-italian-users-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-AGID avverte di una nuova campagna di phishing che abusa del marchio SPID e AgID per rubare dati personali e bancari tramite domini contenenti 'spid' e 'gov'."
original_url: "https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/"
source: "CERT-AgID"
severity: "Medium"
target: "Utenti italiani SPID"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-AGID avverte di una nuova campagna di phishing che abusa del marchio SPID e AgID per rubare dati personali e bancari tramite domini contenenti 'spid' e 'gov'.

{{< cyber-report severity="Medium" source="CERT-AgID" target="Utenti italiani SPID" >}}

CERT-AGID ha identificato una campagna di phishing in corso che abusa del tema SPID (Sistema Pubblico di Identità Digitale) per acquisire fraudolentemente informazioni personali e bancarie dagli utenti italiani. La campagna sfrutta i nomi e i loghi ufficiali di AgID e SPID per aumentare la propria credibilità, rendendola particolarmente ingannevole.

{{< ad-banner >}}

Gli aggressori stanno utilizzando molteplici domini che incorporano i termini 'spid' e 'gov' nei loro nomi, una tattica progettata per indurre gli utenti a credere di interagire con servizi governativi legittimi. Questo approccio sfrutta la fiducia che gli utenti ripongono in domini e marchi dall'aspetto ufficiale.

Sebbene il vettore d'attacco esatto (ad esempio, email, SMS) non sia specificato nell'avviso, l'obiettivo della campagna è chiaro: raccogliere dati sensibili. Si consiglia agli utenti di verificare l'autenticità di qualsiasi comunicazione che richieda informazioni personali o bancarie e di segnalare messaggi sospetti alle autorità competenti.

{{< netrunner-insight >}}

Per gli analisti SOC, questa campagna sottolinea l'importanza di monitorare i domini simili che combinano termini di marchi fidati con 'gov' o TLD simili. Implementare regole di filtraggio email che segnalino messaggi contenenti tali domini e istruire gli utenti a verificare gli URL prima di fare clic. I team DevSecOps dovrebbero considerare l'integrazione di feed di reputazione dei domini nel loro stack di sicurezza per bloccare automaticamente questi domini di phishing.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CERT-AgID ›](https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/)**
