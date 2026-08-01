---
title: "Le chargeur HollowFrame et la porte dérobée Matryoshka ciblent un cabinet d'avocats"
date: "2026-08-01T09:01:20Z"
original_date: "2026-07-31T16:39:31"
lang: "fr"
translationKey: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
slug: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
author: "NewsBot (Validated by Federico Sella)"
description: "Un nouveau chargeur basé sur Go, HollowFrame, et une porte dérobée basée sur Rust, Matryoshka, ont été utilisés dans une attaque de spear-phishing contre un cabinet d'avocats, selon Blackpoint Cyber."
original_url: "https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html"
source: "The Hacker News"
severity: "High"
target: "Cabinet d'avocats"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un nouveau chargeur basé sur Go, HollowFrame, et une porte dérobée basée sur Rust, Matryoshka, ont été utilisés dans une attaque de spear-phishing contre un cabinet d'avocats, selon Blackpoint Cyber.

{{< cyber-report severity="High" source="The Hacker News" target="Cabinet d'avocats" >}}

Blackpoint Cyber a découvert une chaîne d'attaque inédite ciblant un cabinet d'avocats, commençant par un e-mail de spear-phishing qui incite le destinataire à télécharger une archive chiffrée. L'archive contient un fichier de raccourci Windows (LNK) qui, une fois exécuté, déclenche un processus d'infection en plusieurs étapes.

{{< ad-banner >}}

L'attaque exploite deux familles de logiciels malveillants jusqu'alors non documentées : HollowFrame, un framework de chargeur basé sur Go, et Matryoshka, une porte dérobée basée sur Rust. Le chargeur est responsable de la livraison de la porte dérobée, qui fournit aux attaquants un accès à distance au système compromis.

Cette campagne met en évidence l'évolution continue des outils malveillants, les attaquants adoptant des langages multiplateformes comme Go et Rust pour échapper à la détection et compliquer l'analyse. L'utilisation d'archives chiffrées et de fichiers LNK dans le spear-phishing est une tactique courante, mais la combinaison de ces outils spécifiques ajoute une nouvelle couche de sophistication.

{{< netrunner-insight >}}

Les analystes SOC devraient prioriser la surveillance des exécutions de fichiers LNK et des téléchargements d'archives à partir de liens e-mail, car ce sont des indicateurs précoces de cette chaîne d'attaque. Les équipes DevSecOps devraient envisager de bloquer ou de sandboxer l'exécution de fichiers provenant d'archives chiffrées, et s'assurer que les solutions de détection et de réponse aux points de terminaison (EDR) sont configurées pour détecter les binaires Go et Rust présentant un comportement de chargeur.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html)**
