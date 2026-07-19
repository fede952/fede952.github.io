---
title: "Sept paquets npm malveillants ciblent l'écosystème Vite avec un C2 basé sur la blockchain"
date: "2026-07-19T09:03:59Z"
original_date: "2026-07-17T18:54:51"
lang: "fr"
translationKey: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
slug: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
author: "NewsBot (Validated by Federico Sella)"
description: "Checkmarx découvre la campagne ViteVenom utilisant une infrastructure C2 basée sur la blockchain pour livrer un RAT via sept paquets npm malveillants ciblant l'outillage frontend Vite."
original_url: "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
source: "The Hacker News"
severity: "High"
target: "Écosystème d'outillage frontend Vite"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Checkmarx découvre la campagne ViteVenom utilisant une infrastructure C2 basée sur la blockchain pour livrer un RAT via sept paquets npm malveillants ciblant l'outillage frontend Vite.

{{< cyber-report severity="High" source="The Hacker News" target="Écosystème d'outillage frontend Vite" >}}

Des chercheurs en cybersécurité de Checkmarx ont identifié un groupe de sept paquets npm malveillants ciblant l'écosystème d'outillage frontend Vite dans le cadre d'une attaque sur la chaîne d'approvisionnement logicielle. La campagne, baptisée ViteVenom, représente une expansion de l'opération ChainVeil observée précédemment, qui utilisait une infrastructure de commande et de contrôle (C2) basée sur la blockchain à quatre niveaux sans précédent, couvrant le réseau Tron.

{{< ad-banner >}}

Les paquets malveillants sont conçus pour livrer un cheval de Troie d'accès à distance (RAT) aux systèmes compromis, permettant aux attaquants d'exfiltrer des données et de maintenir un accès persistant. L'utilisation de la blockchain pour les communications C2 rend la détection et le démantèlement plus difficiles, car l'infrastructure est décentralisée et résistante aux techniques traditionnelles de sinkholing.

Les organisations utilisant Vite dans leurs pipelines de développement doivent immédiatement auditer leurs dépendances pour détecter les paquets malveillants identifiés et mettre en œuvre des contrôles stricts d'intégrité des paquets. Cet incident met en évidence la sophistication croissante des attaques sur la chaîne d'approvisionnement logicielle, où les attaquants exploitent des outils de développement légitimes et des réseaux décentralisés pour échapper à la détection.

{{< netrunner-insight >}}

Pour les analystes SOC, la surveillance des connexions sortantes vers les nœuds de la blockchain et des requêtes DNS inhabituelles peut aider à détecter cette technique C2. Les équipes DevSecOps doivent imposer la signature des paquets et utiliser des outils d'analyse des dépendances pour bloquer les paquets malveillants connus avant qu'ils n'entrent dans le pipeline de construction.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html)**
