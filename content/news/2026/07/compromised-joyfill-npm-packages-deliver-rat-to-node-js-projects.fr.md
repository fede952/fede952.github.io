---
title: "Paquets npm joyfill compromis livrant un RAT aux projets Node.js"
date: "2026-07-29T09:34:53Z"
original_date: "2026-07-29T04:20:57"
lang: "fr"
translationKey: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
slug: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
author: "NewsBot (Validated by Federico Sella)"
description: "Les versions bêta de @joyfill/layouts et @joyfill/components contiennent un implant JavaScript au moment de l'importation qui résout du code chiffré pour déployer un cheval de Troie d'accès à distance."
original_url: "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "Développeurs Node.js utilisant les paquets joyfill"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Les versions bêta de @joyfill/layouts et @joyfill/components contiennent un implant JavaScript au moment de l'importation qui résout du code chiffré pour déployer un cheval de Troie d'accès à distance.

{{< cyber-report severity="High" source="The Hacker News" target="Développeurs Node.js utilisant les paquets joyfill" >}}

Deux paquets npm dans l'espace de noms @joyfill, @joyfill/layouts version 0.1.2-2773.beta.0 et @joyfill/components version 4.0.0-rc24-2773-beta.4, ont été compromis. Ces versions bêta contiennent un implant JavaScript au moment de l'importation qui résout du code chiffré, livrant finalement un cheval de Troie d'accès à distance (RAT) associé à la famille de malwares DEV#POPPER.

{{< ad-banner >}}

Le code malveillant s'exécute lorsque les paquets sont importés dans un projet Node.js, donnant aux attaquants un accès à distance au système compromis. Cette attaque met en évidence le risque persistant des attaques sur la chaîne d'approvisionnement ciblant l'écosystème npm, en particulier via les versions bêta ou release candidate qui peuvent recevoir moins de contrôle.

Les développeurs qui ont utilisé ces versions spécifiques doivent immédiatement faire pivoter leurs identifiants, rechercher des indicateurs de compromission et examiner leurs arbres de dépendances pour tout autre paquet suspect. Le registre npm a probablement supprimé les versions malveillantes, mais les installations existantes restent une menace.

{{< netrunner-insight >}}

Cet incident souligne l'importance d'examiner les paquets de pré-version et de mettre en œuvre des contrôles d'intégrité des dépendances. Les analystes SOC doivent surveiller les connexions sortantes inhabituelles depuis les applications Node.js, tandis que les équipes DevSecOps doivent imposer un épinglage strict des versions et utiliser des outils comme npm audit ou les scanners SCA pour détecter les paquets malveillants connus.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html)**
