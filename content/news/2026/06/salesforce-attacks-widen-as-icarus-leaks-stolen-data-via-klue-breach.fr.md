---
title: "Les attaques contre Salesforce s'intensifient alors qu'Icarus divulgue des données volées via la brèche Klue"
date: "2026-06-24T10:22:11Z"
original_date: "2026-06-23T20:44:09"
lang: "fr"
translationKey: "salesforce-attacks-widen-as-icarus-leaks-stolen-data-via-klue-breach"
author: "NewsBot (Validated by Federico Sella)"
description: "Les attaquants ont exploité les jetons OAuth de Klue pour accéder à des instances Salesforce ; de nouvelles victimes émergent alors qu'Icarus divulgue les données volées."
original_url: "https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data"
source: "Dark Reading"
severity: "High"
target: "Instances Salesforce via les jetons OAuth de Klue"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Les attaquants ont exploité les jetons OAuth de Klue pour accéder à des instances Salesforce ; de nouvelles victimes émergent alors qu'Icarus divulgue les données volées.

{{< cyber-report severity="High" source="Dark Reading" target="Instances Salesforce via les jetons OAuth de Klue" >}}

L'ampleur des attaques en cours contre Salesforce s'est élargie alors que des acteurs malveillants, suivis sous le nom d'Icarus, divulguent des données volées à plusieurs victimes. Les attaquants ont d'abord compromis le fournisseur d'applications Klue et ont utilisé ses jetons OAuth pour obtenir un accès non autorisé aux environnements Salesforce des clients.

{{< ad-banner >}}

Selon Dark Reading, de nouvelles victimes sont apparues après la divulgation initiale, indiquant que la campagne d'attaque est plus large que ce qui était compris auparavant. L'utilisation de jetons OAuth a permis aux attaquants de contourner les contrôles d'authentification traditionnels et d'accéder directement aux données Salesforce sans déclencher d'alertes typiques.

Les organisations utilisant des intégrations Salesforce avec des fournisseurs tiers comme Klue sont invitées à auditer les permissions des jetons OAuth et à surveiller les schémas d'accès anormaux. Le groupe Icarus a commencé à divulguer des données volées, augmentant l'urgence pour les entreprises concernées de réagir.

{{< netrunner-insight >}}

Cette attaque souligne le risque d'abus de jetons OAuth dans les écosystèmes SaaS. Les analystes SOC devraient prioriser la surveillance des appels API inhabituels et de l'utilisation de jetons provenant d'applications tierces intégrées. Les équipes DevSecOps doivent imposer une gestion stricte du cycle de vie des jetons et mettre en œuvre des permissions juste-à-temps pour limiter le rayon d'explosion.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur Dark Reading ›](https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data)**
