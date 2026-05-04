---
title: "Paquets dormants dans les gems Ruby et les modules Go ciblant les pipelines CI/CD"
date: "2026-05-04T09:17:53Z"
original_date: "2026-05-01T09:43:00"
lang: "fr"
translationKey: "sleeper-packages-in-ruby-gems-and-go-modules-target-ci-cd-pipelines"
author: "NewsBot (Validated by Federico Sella)"
description: "Les attaquants utilisent des paquets dormants pour livrer des charges utiles malveillantes, voler des identifiants, falsifier les actions GitHub et établir une persistance SSH dans les attaques sur la chaîne d'approvisionnement logicielle."
original_url: "https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html"
source: "The Hacker News"
severity: "High"
target: "pipelines CI/CD et chaînes d'approvisionnement logicielles"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Les attaquants utilisent des paquets dormants pour livrer des charges utiles malveillantes, voler des identifiants, falsifier les actions GitHub et établir une persistance SSH dans les attaques sur la chaîne d'approvisionnement logicielle.

{{< cyber-report severity="High" source="The Hacker News" target="pipelines CI/CD et chaînes d'approvisionnement logicielles" >}}

Une nouvelle campagne d'attaque sur la chaîne d'approvisionnement logicielle a été observée, utilisant des paquets dormants comme conduit pour pousser ultérieurement des charges utiles malveillantes permettant le vol d'identifiants, la falsification des actions GitHub et la persistance SSH. L'activité a été attribuée au compte GitHub "BufferZoneCorp", qui a publié un ensemble de dépôts associés à des gems Ruby et des modules Go malveillants.

{{< ad-banner >}}

L'attaque exploite des paquets d'apparence bénigne qui reçoivent ensuite des mises à jour malveillantes, une technique connue sous le nom de paquets "dormants" ou "trojanisés". Une fois installés dans les environnements CI/CD, les charges utiles volent des identifiants, modifient les workflows GitHub Actions et établissent un accès SSH persistant, posant une menace significative pour les pipelines de développement.

Les organisations utilisant des gems Ruby ou des modules Go provenant de sources non fiables devraient auditer leurs dépendances et surveiller les activités suspectes des dépôts. Cette campagne souligne la sophistication croissante des attaques sur la chaîne d'approvisionnement ciblant l'infrastructure des développeurs.

{{< netrunner-insight >}}

Cette campagne souligne la nécessité d'un épinglage strict des dépendances et d'une vérification de l'intégrité dans les pipelines CI/CD. Les analystes SOC doivent surveiller les modifications anormales des actions GitHub et les ajouts de clés SSH, tandis que les ingénieurs DevSecOps doivent implémenter un accès de moindre privilège et envisager d'utiliser des environnements de construction éphémères pour limiter l'impact.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html)**
