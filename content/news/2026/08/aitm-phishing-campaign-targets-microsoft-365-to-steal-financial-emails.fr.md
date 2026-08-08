---
title: "Campagne de phishing AitM ciblant Microsoft 365 pour voler des e-mails financiers"
date: "2026-08-08T07:47:42Z"
original_date: "2026-08-07T10:38:27"
lang: "fr"
translationKey: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
slug: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
author: "NewsBot (Validated by Federico Sella)"
description: "Une campagne de phishing généralisée par e-mail utilise l'homme du milieu pour détourner des comptes Microsoft 365, visant à collecter des e-mails de paie et de finance."
original_url: "https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html"
source: "The Hacker News"
severity: "High"
target: "Comptes Microsoft 365"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Une campagne de phishing généralisée par e-mail utilise l'homme du milieu pour détourner des comptes Microsoft 365, visant à collecter des e-mails de paie et de finance.

{{< cyber-report severity="High" source="The Hacker News" target="Comptes Microsoft 365" >}}

Des chercheurs en cybersécurité ont identifié une campagne de phishing active et généralisée par e-mail qui exploite des techniques d'homme du milieu (AitM) pour compromettre des comptes Microsoft 365. L'objectif principal de cette campagne est d'identifier les personnes clés impliquées dans les flux de travail financiers et d'exfiltrer les communications par e-mail associées, en particulier celles concernant la paie et les finances.

{{< ad-banner >}}

Les attaquants utilisent des proxys résidentiels pour déguiser leurs connexions malveillantes en trafic de consommation ordinaire, évitant ainsi la détection par les contrôles de sécurité qui signalent généralement les adresses IP suspectes. Cette technique permet aux attaquants de maintenir une persistance et un accès aux comptes compromis sans déclencher d'alertes immédiates.

Les organisations utilisant Microsoft 365 doivent être vigilantes face à de telles tentatives de phishing AitM, qui contournent souvent l'authentification multifacteur en relayant les identifiants et les jetons de session en temps réel. L'accent mis par la campagne sur les données financières suggère un effort ciblé pour faciliter la fraude financière ou la compromission d'e-mails professionnels (BEC).

{{< netrunner-insight >}}

Cette campagne souligne la nécessité d'une MFA résistante au phishing, comme les clés de sécurité FIDO2, et d'une surveillance continue des connexions anormales, en particulier celles provenant de plages IP résidentielles. Les équipes SOC devraient également prioriser les règles de détection pour les kits d'outils AitM et appliquer des politiques d'accès conditionnel qui restreignent l'accès en fonction des signaux de risque. Les ingénieurs DevSecOps devraient envisager de mettre en œuvre la liaison de session et des contrôles de conformité des appareils pour atténuer les attaques de relais de jetons.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html)**
