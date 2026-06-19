---
title: "DragonForce utilise les relais Microsoft Teams pour dissimuler le trafic C2 de Backdoor.Turn"
date: "2026-06-19T11:15:07Z"
original_date: "2026-06-18T13:30:07"
lang: "fr"
translationKey: "dragonforce-uses-microsoft-teams-relays-to-hide-backdoor-turn-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Le groupe de ransomware DragonForce déploie un RAT personnalisé en Go, Backdoor.Turn, dissimulant le trafic C2 dans les relais Microsoft Teams, ciblant une grande entreprise de services américaine."
original_url: "https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html"
source: "The Hacker News"
severity: "High"
target: "Grande entreprise de services américaine"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Le groupe de ransomware DragonForce déploie un RAT personnalisé en Go, Backdoor.Turn, dissimulant le trafic C2 dans les relais Microsoft Teams, ciblant une grande entreprise de services américaine.

{{< cyber-report severity="High" source="The Hacker News" target="Grande entreprise de services américaine" >}}

Des acteurs malveillants associés au groupe de ransomware DragonForce ont été observés utilisant un cheval de Troie d'accès à distance (RAT) personnalisé en Go, appelé Backdoor.Turn, pour dissimuler le trafic de commande et de contrôle (C2) dans l'infrastructure de relais Microsoft Teams. La porte dérobée a été déployée contre une grande entreprise de services américaine, selon des conclusions de Symantec et Carbon Black, propriétés de Broadcom.

{{< ad-banner >}}

En exploitant les relais légitimes de Microsoft Teams, les attaquants peuvent mélanger le trafic malveillant avec les communications professionnelles normales, rendant la détection plus difficile pour les défenseurs réseau. Le RAT en Go offre aux attaquants un accès persistant et la capacité d'exécuter des commandes, d'exfiltrer des données et de déployer des charges utiles supplémentaires.

Cette technique met en évidence l'évolution des tactiques des groupes de ransomware pour contourner les outils de surveillance réseau traditionnels. Les organisations utilisant Microsoft Teams devraient revoir leurs configurations de sécurité et surveiller les schémas de trafic de relais anormaux.

{{< netrunner-insight >}}

Les analystes SOC doivent surveiller le trafic inhabituel des relais Microsoft Teams, en particulier depuis des points de terminaison non standard ou en dehors des heures de travail. Les équipes DevSecOps doivent appliquer une liste blanche stricte des applications et inspecter le trafic Teams pour détecter des tunnels chiffrés pouvant indiquer une communication C2. Cette attaque souligne la nécessité de principes de confiance zéro même pour les plateformes de collaboration de confiance.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html)**
