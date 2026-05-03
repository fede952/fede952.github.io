---
title: "Les packages npm SAP touchés par une attaque de la chaîne d'approvisionnement volant des identifiants"
date: "2026-05-03T08:51:39Z"
original_date: "2026-04-29T16:26:00"
lang: "fr"
translationKey: "sap-npm-packages-hit-by-credential-stealing-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Une campagne baptisée 'Mini Shai-Hulud' cible les packages npm liés à SAP avec un malware volant des identifiants, affectant plusieurs packages. Des chercheurs de plusieurs entreprises mettent en garde contre les risques liés à la chaîne d'approvisionnement."
original_url: "https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html"
source: "The Hacker News"
severity: "High"
target: "Packages npm liés à SAP"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Une campagne baptisée 'Mini Shai-Hulud' cible les packages npm liés à SAP avec un malware volant des identifiants, affectant plusieurs packages. Des chercheurs de plusieurs entreprises mettent en garde contre les risques liés à la chaîne d'approvisionnement.

{{< cyber-report severity="High" source="The Hacker News" target="Packages npm liés à SAP" >}}

Des chercheurs en cybersécurité ont découvert une campagne d'attaque de la chaîne d'approvisionnement ciblant les packages npm liés à SAP. Baptisée 'Mini Shai-Hulud', la campagne déploie un malware volant des identifiants via des packages compromis, selon des rapports d'Aikido Security, Onapsis, OX Security, SafeDep, Socket, StepSecurity et Wiz.

{{< ad-banner >}}

L'attaque affecte plusieurs packages npm associés à SAP, bien que les noms et versions spécifiques des packages n'aient pas été divulgués. Le malware est conçu pour voler des identifiants, donnant potentiellement aux attaquants un accès aux environnements SAP sensibles et aux systèmes en aval.

Cet incident met en lumière la menace croissante pesant sur les chaînes d'approvisionnement logicielles, en particulier pour les plateformes critiques d'entreprise comme SAP. Les organisations utilisant des packages affectés sont invitées à auditer leurs dépendances et à renouveler tout identifiant potentiellement compromis.

{{< netrunner-insight >}}

Pour les analystes SOC et les équipes DevSecOps, cette attaque souligne la nécessité d'une analyse rigoureuse des dépendances et de vérifications d'intégrité sur les packages npm. Surveillez les connexions sortantes inhabituelles depuis les systèmes liés à SAP et envisagez de mettre en œuvre une protection d'auto-défense des applications au moment de l'exécution (RASP) pour détecter le vol d'identifiants. Renouvelez immédiatement tous les identifiants qui ont pu être exposés via des packages compromis.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)**
