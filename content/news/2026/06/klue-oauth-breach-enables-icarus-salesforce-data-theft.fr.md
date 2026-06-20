---
title: "Violation OAuth chez Klue permet le vol de données Salesforce par Icarus"
date: "2026-06-20T10:03:21Z"
original_date: "2026-06-18T14:19:50"
lang: "fr"
translationKey: "klue-oauth-breach-enables-icarus-salesforce-data-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "Des acteurs malveillants ont exploité une violation OAuth chez Klue pour dérober des données CRM Salesforce à plusieurs organisations dans le cadre d'une campagne d'extorsion en cours."
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/"
source: "BleepingComputer"
severity: "High"
target: "Données CRM Salesforce via OAuth"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Des acteurs malveillants ont exploité une violation OAuth chez Klue pour dérober des données CRM Salesforce à plusieurs organisations dans le cadre d'une campagne d'extorsion en cours.

{{< cyber-report severity="High" source="BleepingComputer" target="Données CRM Salesforce via OAuth" >}}

La plateforme de veille concurrentielle Klue a subi une violation OAuth qui a permis au groupe d'acteurs malveillants connu sous le nom d'Icarus de dérober des données CRM Salesforce à plusieurs organisations. Les attaquants ont exploité des jetons OAuth compromis pour accéder et exfiltrer des données sensibles de gestion de la relation client, qu'ils utilisent désormais dans une campagne d'extorsion.

{{< ad-banner >}}

Cette violation met en lumière les risques associés aux intégrations OAuth et à l'accès tiers à des plateformes métier critiques. Les organisations utilisant les services de Klue sont invitées à revoir leurs politiques de jetons OAuth et à surveiller les accès non autorisés aux instances Salesforce.

Icarus a été lié à une série d'attaques de vol de données ciblant des environnements Salesforce. Le mode opératoire du groupe consiste à exploiter des configurations OAuth faibles et des pratiques de gestion des jetons pour obtenir un accès persistant aux données CRM.

{{< netrunner-insight >}}

Cet incident souligne le besoin crucial d'une gestion rigoureuse du cycle de vie des jetons OAuth et d'une surveillance continue des intégrations tierces. Les analystes SOC devraient prioriser l'audit des autorisations OAuth et la mise en œuvre de la détection d'anomalies pour les schémas d'accès inhabituels aux données provenant d'applications intégrées.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/)**
