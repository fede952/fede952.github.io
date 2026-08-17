---
title: "Campagne de phishing sur le thème de SPID ciblant les identifiants des utilisateurs italiens"
date: "2026-08-17T07:50:54Z"
original_date: "2026-08-03T11:05:05"
lang: "fr"
translationKey: "spid-themed-phishing-campaign-targets-italian-users-credentials"
slug: "spid-themed-phishing-campaign-targets-italian-users-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-AGID met en garde contre une nouvelle campagne de phishing qui abuse de l'image de marque de SPID et d'AgID pour voler des données personnelles et bancaires via des domaines contenant 'spid' et 'gov'."
original_url: "https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/"
source: "CERT-AgID"
severity: "Medium"
target: "Utilisateurs italiens de SPID"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-AGID met en garde contre une nouvelle campagne de phishing qui abuse de l'image de marque de SPID et d'AgID pour voler des données personnelles et bancaires via des domaines contenant 'spid' et 'gov'.

{{< cyber-report severity="Medium" source="CERT-AgID" target="Utilisateurs italiens de SPID" >}}

CERT-AGID a identifié une campagne de phishing en cours qui abuse du thème SPID (Sistema Pubblico di Identità Digitale) pour acquérir frauduleusement des informations personnelles et bancaires auprès des utilisateurs italiens. La campagne exploite les noms et logos officiels d'AgID et de SPID pour renforcer sa crédibilité, ce qui la rend particulièrement trompeuse.

{{< ad-banner >}}

Les attaquants utilisent plusieurs domaines qui intègrent les termes 'spid' et 'gov' dans leurs noms, une tactique conçue pour faire croire aux utilisateurs qu'ils interagissent avec des services gouvernementaux légitimes. Cette approche exploite la confiance que les utilisateurs accordent aux domaines et à l'image de marque à l'apparence officielle.

Bien que le vecteur d'attaque exact (par exemple, e-mail, SMS) ne soit pas spécifié dans l'avis, l'objectif de la campagne est clair : collecter des données sensibles. Il est conseillé aux utilisateurs de vérifier l'authenticité de toute communication demandant des informations personnelles ou bancaires et de signaler les messages suspects aux autorités compétentes.

{{< netrunner-insight >}}

Pour les analystes SOC, cette campagne souligne l'importance de surveiller les domaines ressemblant à des domaines légitimes qui combinent des termes de marque de confiance avec 'gov' ou des TLD similaires. Mettez en œuvre des règles de filtrage des e-mails qui signalent les messages contenant de tels domaines, et sensibilisez les utilisateurs à vérifier les URL avant de cliquer. Les équipes DevSecOps devraient envisager d'intégrer des flux de réputation de domaine dans leur pile de sécurité pour bloquer automatiquement ces domaines de phishing.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CERT-AgID ›](https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/)**
