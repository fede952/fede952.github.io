---
title: "LastPass confirme une fuite de données via une attaque sur la chaîne d'approvisionnement de Klue"
date: "2026-06-24T10:23:36Z"
original_date: "2026-06-23T13:58:25"
lang: "fr"
translationKey: "lastpass-confirms-data-breach-via-klue-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "LastPass a révélé que des attaquants ont volé des jetons OAuth d'une application tierce, Klue, pour accéder aux données clients dans son environnement Salesforce."
original_url: "https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Environnement Salesforce de LastPass"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

LastPass a révélé que des attaquants ont volé des jetons OAuth d'une application tierce, Klue, pour accéder aux données clients dans son environnement Salesforce.

{{< cyber-report severity="High" source="BleepingComputer" target="Environnement Salesforce de LastPass" >}}

LastPass a confirmé que des pirates ont accédé aux données clients de son environnement Salesforce après avoir volé les jetons OAuth de l'entreprise lors de l'attaque sur la chaîne d'approvisionnement de Klue plus tôt ce mois-ci. La fuite, divulguée le 23 juin 2026, met en lumière les risques liés aux intégrations tierces et au vol de jetons.

{{< ad-banner >}}

Les attaquants ont utilisé des jetons OAuth compromis de Klue, une application tierce, pour obtenir un accès non autorisé à l'instance Salesforce de LastPass. Cette attaque sur la chaîne d'approvisionnement a permis aux acteurs malveillants d'exfiltrer des données clients sans déclencher les alertes d'authentification habituelles.

LastPass informe les clients concernés et a révoqué les jetons compromis. L'entreprise examine également ses politiques d'accès tiers pour éviter des incidents similaires. Cette fuite souligne l'importance de surveiller l'utilisation des jetons OAuth et de mettre en place des contrôles d'accès stricts pour les services intégrés.

{{< netrunner-insight >}}

Cet incident est un exemple typique de risque lié à la chaîne d'approvisionnement via l'abus de jetons OAuth. Les analystes SOC devraient prioriser la surveillance des utilisations anormales de jetons et mettre en place des politiques d'expiration des jetons. Les équipes DevSecOps doivent appliquer le principe du moindre privilège pour les intégrations tierces et envisager l'utilisation de jetons à courte durée de vie pour réduire l'impact potentiel.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/)**
