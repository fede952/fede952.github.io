---
title: "CISA met en garde contre un contournement critique de l'authentification dans Rockwell FactoryTalk Analytics PavilionX"
date: "2026-06-18T11:06:01Z"
original_date: "2026-06-16T12:00:00"
lang: "fr"
translationKey: "cisa-warns-of-critical-auth-bypass-in-rockwell-factorytalk-analytics-pavilionx"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerte sur CVE-2025-14272 affectant Rockwell Automation FactoryTalk Analytics PavilionX <7.01, permettant des opérations privilégiées non autorisées dans des environnements de fabrication critiques."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01"
source: "CISA"
severity: "High"
target: "Rockwell FactoryTalk Analytics PavilionX"
cve: "CVE-2025-14272"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerte sur CVE-2025-14272 affectant Rockwell Automation FactoryTalk Analytics PavilionX <7.01, permettant des opérations privilégiées non autorisées dans des environnements de fabrication critiques.

{{< cyber-report severity="High" source="CISA" target="Rockwell FactoryTalk Analytics PavilionX" cve="CVE-2025-14272" >}}

CISA a publié un avis (ICSA-26-167-01) concernant une vulnérabilité d'absence d'autorisation dans Rockwell Automation FactoryTalk Analytics PavilionX. La faille, suivie sous le nom CVE-2025-14272, affecte les versions antérieures à 7.01 et permet à un attaquant non autorisé d'exécuter des opérations privilégiées telles que la gestion des utilisateurs et des rôles.

{{< ad-banner >}}

La vulnérabilité provient d'une application incorrecte des autorisations dans les points de terminaison API. Une exploitation réussie pourrait conduire à un contrôle administratif complet du système affecté. Rockwell Automation a publié la version 7.01 pour corriger le problème, et les utilisateurs sont invités à mettre à jour immédiatement.

Compte tenu du déploiement de ce produit dans des secteurs de fabrication critiques dans le monde entier, le risque de perturbation opérationnelle ou de compromission des données est significatif. Les organisations doivent prioriser le déploiement des correctifs et revoir les contrôles d'accès pour atténuer une éventuelle exploitation.

{{< netrunner-insight >}}

Il s'agit d'un contournement d'autorisation classique qui doit être traité comme un correctif de haute priorité. Les analystes SOC doivent surveiller les appels API anormaux ou les escalades de privilèges dans les environnements PavilionX. Les équipes DevSecOps doivent s'assurer que la version 7.01 est déployée et que la segmentation réseau limite l'exposition de ces points de terminaison.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01)**
