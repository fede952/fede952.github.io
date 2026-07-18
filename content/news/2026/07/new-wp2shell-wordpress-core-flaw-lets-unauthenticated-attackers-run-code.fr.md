---
title: "Nouvelle faille wp2shell dans le cœur de WordPress permet à des attaquants non authentifiés d'exécuter du code"
date: "2026-07-18T08:47:36Z"
original_date: "2026-07-17T21:20:10"
lang: "fr"
translationKey: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
slug: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
author: "NewsBot (Validated by Federico Sella)"
description: "Une requête HTTP anonyme peut exécuter du code sur les sites WordPress. Le bogue affecte le cœur, donc même les installations nues sont exploitables. Tous les sites en version 6.9 et 7.0 étaient concernés jusqu'à la correction."
original_url: "https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html"
source: "The Hacker News"
severity: "Critical"
target: "Cœur de WordPress (versions 6.9 et 7.0)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Une requête HTTP anonyme peut exécuter du code sur les sites WordPress. Le bogue affecte le cœur, donc même les installations nues sont exploitables. Tous les sites en version 6.9 et 7.0 étaient concernés jusqu'à la correction.

{{< cyber-report severity="Critical" source="The Hacker News" target="Cœur de WordPress (versions 6.9 et 7.0)" >}}

Une vulnérabilité critique d'exécution de code à distance non authentifiée a été découverte dans le cœur de WordPress, affectant les versions 6.9 et 7.0. La faille, surnommée wp2shell, permet à un attaquant d'exécuter du code arbitraire sur un site cible en envoyant une requête HTTP spécialement conçue. Notamment, la vulnérabilité existe dans le logiciel de base, ce qui signifie que même une installation fraîche de WordPress sans plugin est exploitable.

{{< ad-banner >}}

Les détails techniques complets et une preuve de concept fonctionnelle ont été publiés, ainsi que des identifiants CVE attribués aux deux failles sous-jacentes. Une condition de cache d'objet persistant a également été identifiée, ce qui peut compliquer l'exploitation dans certains environnements. Tous les sites exécutant les versions affectées étaient considérés à risque jusqu'à l'application des correctifs.

Les administrateurs sont invités à mettre à jour immédiatement vers la dernière version corrigée. Compte tenu de la facilité d'exploitation et de l'utilisation généralisée de WordPress, cette vulnérabilité constitue une menace importante pour la sécurité Web. Les organisations doivent prioriser la correction et examiner les règles de leur pare-feu d'application Web pour détecter et bloquer les tentatives d'exploitation.

{{< netrunner-insight >}}

C'est un exemple typique de pourquoi le logiciel de base doit être durci contre les attaques non authentifiées. Les analystes SOC doivent immédiatement rechercher les instances WordPress 6.9 et 7.0 et vérifier l'état des correctifs. Les équipes DevSecOps doivent considérer cela comme un rappel pour implémenter l'auto-protection des applications au moment de l'exécution (RASP) et surveiller les requêtes HTTP anormales ciblant wp-admin ou wp-includes.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html)**
