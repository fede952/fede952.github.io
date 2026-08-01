---
title: "Un hacker chinois utilise DeepSeek via Telegram pour lancer des attaques autonomes"
date: "2026-08-01T09:07:32Z"
original_date: "2026-07-31T11:21:27"
lang: "fr"
translationKey: "chinese-hacker-uses-deepseek-via-telegram-to-launch-autonomous-attacks"
slug: "chinese-hacker-uses-deepseek-via-telegram-to-launch-autonomous-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "Unit 42 signale qu'un acteur de menace sinophone exploite DeepSeek via Hermes Agent pour attaquer de manière autonome des systèmes exposés à Internet après une seule commande Telegram."
original_url: "https://thehackernews.com/2026/07/chinese-hacker-commands-deepseek-via.html"
source: "The Hacker News"
severity: "High"
target: "Systèmes exposés à Internet"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Unit 42 signale qu'un acteur de menace sinophone exploite DeepSeek via Hermes Agent pour attaquer de manière autonome des systèmes exposés à Internet après une seule commande Telegram.

{{< cyber-report severity="High" source="The Hacker News" target="Systèmes exposés à Internet" >}}

L'Unit 42 de Palo Alto Networks a révélé une chaîne d'attaque inédite dans laquelle un acteur de menace sinophone, suivi sous les alias knaithe et KnYuan, a utilisé le modèle d'IA DeepSeek via le framework open-source Hermes Agent pour mener des attaques autonomes. L'opération a commencé par une simple instruction Telegram, après quoi l'agent a identifié de manière indépendante les systèmes exposés à Internet et sélectionné les exploits publics appropriés.

{{< ad-banner >}}

Selon les chercheurs, aucune autre intervention de l'opérateur n'a été détectée pendant la session, ce qui indique un degré élevé d'automatisation. Cela marque une évolution significative dans les cyberattaques assistées par l'IA, où l'agent IA gère la reconnaissance, la sélection des exploits et l'exécution sans direction humaine continue.

Ces résultats soulignent la menace croissante des outils d'attaque autonomes pilotés par l'IA, qui abaissent la barrière pour les attaquants moins qualifiés et augmentent la vitesse et l'échelle des opérations. Les organisations doivent adapter leurs défenses pour contrer ces menaces automatisées, qui peuvent opérer à la vitesse de la machine et s'adapter à leur environnement.

{{< netrunner-insight >}}

Cet incident souligne le besoin urgent pour les SOC de surveiller les schémas d'attaque pilotés par l'IA, tels que les tentatives d'exploitation rapides et automatisées qui peuvent manquer des signatures typiques d'erreur humaine. Les équipes DevSecOps devraient prioriser le durcissement des actifs exposés à Internet et mettre en œuvre des mécanismes automatisés de détection et de réponse pour contrer les menaces autonomes. De plus, envisagez de restreindre l'accès aux modèles d'IA et de surveiller les utilisations inhabituelles de l'API qui pourraient indiquer des attaques assistées par l'IA.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/chinese-hacker-commands-deepseek-via.html)**
