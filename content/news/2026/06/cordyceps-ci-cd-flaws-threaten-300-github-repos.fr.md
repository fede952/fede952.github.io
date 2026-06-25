---
title: "Les failles CI/CD Cordyceps menacent plus de 300 dépôts GitHub"
date: "2026-06-25T10:14:17Z"
original_date: "2026-06-24T12:48:11"
lang: "fr"
translationKey: "cordyceps-ci-cd-flaws-threaten-300-github-repos"
author: "NewsBot (Validated by Federico Sella)"
description: "Une nouvelle faiblesse des workflows CI/CD, baptisée Cordyceps, permet aux attaquants de détourner des workflows et de compromettre les chaînes d'approvisionnement open-source de grandes organisations."
original_url: "https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html"
source: "The Hacker News"
severity: "Critical"
target: "Workflows CI/CD sur GitHub"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Une nouvelle faiblesse des workflows CI/CD, baptisée Cordyceps, permet aux attaquants de détourner des workflows et de compromettre les chaînes d'approvisionnement open-source de grandes organisations.

{{< cyber-report severity="Critical" source="The Hacker News" target="Workflows CI/CD sur GitHub" >}}

Des chercheurs en cybersécurité de Novee Security ont identifié un motif exploitable critique dans les workflows CI/CD, surnommé Cordyceps, qui permet aux attaquants de détourner des workflows et de compromettre les chaînes d'approvisionnement open-source. La faille affecte plus de 300 dépôts GitHub appartenant à de grandes organisations, notamment Microsoft, Google et Apache.

{{< ad-banner >}}

Le motif Cordyceps permet un contrôle total des dépôts par l'attaquant, pouvant entraîner des modifications de code non autorisées, l'insertion de portes dérobées et des attaques en aval sur la chaîne d'approvisionnement. La vulnérabilité provient de configurations de workflow non sécurisées qui ne parviennent pas à isoler ou valider correctement les entrées.

Les organisations utilisant GitHub Actions ou des plateformes CI/CD similaires sont invitées à examiner leurs définitions de workflow pour détecter le motif Cordyceps et à mettre en œuvre des permissions au moindre privilège, une désinfection des entrées et un isolement de l'environnement pour atténuer le risque.

{{< netrunner-insight >}}

C'est un vecteur d'attaque de chaîne d'approvisionnement classique. Les analystes SOC doivent surveiller les exécutions de workflow anormales et les modifications inattendues de dépôts. Les équipes DevSecOps doivent auditer immédiatement les configurations de pipeline CI/CD, en se concentrant sur la gestion des entrées non fiables et le cadrage des permissions.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)**
