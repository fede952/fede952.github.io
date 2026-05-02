---
title: "Des défauts dans ABB Ability Symphony Plus Engineering permettent l'exécution de code"
date: "2026-05-02T08:20:38Z"
original_date: "2026-04-30T12:00:00"
lang: "fr"
translationKey: "abb-ability-symphony-plus-engineering-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA met en garde contre des vulnérabilités dans ABB Ability Symphony Plus Engineering dues à une version obsolète de PostgreSQL, permettant l'exécution de code arbitraire sur les systèmes affectés."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06"
source: "CISA"
severity: "High"
target: "ABB Ability Symphony Plus Engineering"
cve: "CVE-2023-5869"
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA met en garde contre des vulnérabilités dans ABB Ability Symphony Plus Engineering dues à une version obsolète de PostgreSQL, permettant l'exécution de code arbitraire sur les systèmes affectés.

{{< cyber-report severity="High" source="CISA" target="ABB Ability Symphony Plus Engineering" cve="CVE-2023-5869" cvss="8.8" >}}

CISA a publié un avis (ICSA-26-120-06) détaillant plusieurs vulnérabilités dans ABB Ability Symphony Plus Engineering, provenant de l'utilisation de PostgreSQL version 13.11 et antérieures. Les failles incluent un débordement d'entier, une injection SQL, une condition de concurrence TOCTOU et des erreurs d'abandon de privilèges, qui pourraient permettre à un attaquant authentifié d'exécuter du code arbitraire sur le système.

{{< ad-banner >}}

Les versions concernées vont de Ability Symphony Plus 2.2 à 2.4 SP2 RU1. Les vulnérabilités sont particulièrement préoccupantes étant donné le déploiement du produit dans des secteurs d'infrastructures critiques tels que la chimie, la fabrication critique, l'énergie, et l'eau et les eaux usées dans le monde entier.

La vulnérabilité la plus notable, CVE-2023-5869, a un score CVSS de 8.8 et implique un débordement d'entier qui peut être déclenché par des données conçues par un utilisateur PostgreSQL authentifié. Une exploitation réussie pourrait entraîner une compromission totale du système, soulignant la nécessité d'une mise à jour immédiate.

{{< netrunner-insight >}}

Cet avis souligne le risque des dépendances obsolètes dans les environnements OT. Les analystes SOC devraient prioriser la découverte d'actifs pour les instances ABB Symphony Plus et s'assurer que PostgreSQL est mis à jour au-delà de la version 13.11. Les équipes DevSecOps doivent intégrer l'analyse des dépendances dans les pipelines CI/CD pour les systèmes de contrôle industriels afin de détecter ces vulnérabilités héritées tôt.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06)**
