---
title: "Violation OAuth chez Klue : les hackers Icarus dérobent des jetons Salesforce"
date: "2026-06-20T09:59:52Z"
original_date: "2026-06-19T22:31:04"
lang: "fr"
translationKey: "klue-oauth-breach-icarus-hackers-steal-salesforce-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Klue confirme un vol de jetons OAuth impactant les intégrations Salesforce ; le groupe d'extorsion Icarus revendique la responsabilité et la liste des victimes s'allonge."
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/"
source: "BleepingComputer"
severity: "High"
target: "plateforme d'intelligence de marché Klue"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Klue confirme un vol de jetons OAuth impactant les intégrations Salesforce ; le groupe d'extorsion Icarus revendique la responsabilité et la liste des victimes s'allonge.

{{< cyber-report severity="High" source="BleepingComputer" target="plateforme d'intelligence de marché Klue" >}}

La plateforme d'intelligence de marché Klue a confirmé un incident de sécurité où des acteurs malveillants ont dérobé des jetons OAuth utilisés pour se connecter aux environnements Salesforce de ses clients. La brèche, revendiquée par le groupe d'extorsion récemment apparu 'Icarus', a conduit à une liste croissante de victimes affectées.

{{< ad-banner >}}

Les jetons OAuth volés pourraient permettre aux attaquants d'accéder aux données Salesforce sans nécessiter d'authentification supplémentaire, posant un risque significatif pour les clients de Klue. L'incident souligne les dangers de l'exposition des jetons OAuth et la nécessité d'une gestion robuste du cycle de vie des jetons.

Alors que le groupe Icarus revendique publiquement l'attaque, les organisations utilisant l'intégration Salesforce de Klue devraient immédiatement révoquer et renouveler tout jeton OAuth associé et surveiller les accès non autorisés. L'ampleur totale de la brèche reste sous enquête.

{{< netrunner-insight >}}

Cet incident souligne l'importance critique de sécuriser les jetons OAuth en tant qu'informations d'identification sensibles. Les analystes SOC devraient prioriser la surveillance des appels API Salesforce anormaux et appliquer des politiques d'expiration des jetons. Les équipes DevSecOps doivent mettre en œuvre des mécanismes stricts de délimitation et de rotation des jetons pour limiter le rayon d'explosion en cas de compromission.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/)**
