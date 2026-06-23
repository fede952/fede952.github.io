---
title: "Paquets npm malveillants déguisés en outils PostCSS livrent un RAT Windows"
date: "2026-06-23T10:35:14Z"
original_date: "2026-06-23T08:54:32"
lang: "fr"
translationKey: "malicious-npm-packages-disguised-as-postcss-tools-deliver-windows-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Trois paquets npm malveillants se faisant passer pour des outils PostCSS ont été découverts en train de livrer un cheval de Troie d'accès à distance Windows. Les chercheurs exhortent à la prudence lors de l'installation de paquets npm."
original_url: "https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html"
source: "The Hacker News"
severity: "High"
target: "utilisateurs npm, systèmes Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Trois paquets npm malveillants se faisant passer pour des outils PostCSS ont été découverts en train de livrer un cheval de Troie d'accès à distance Windows. Les chercheurs exhortent à la prudence lors de l'installation de paquets npm.

{{< cyber-report severity="High" source="The Hacker News" target="utilisateurs npm, systèmes Windows" >}}

Des chercheurs en cybersécurité ont identifié trois paquets npm malveillants—aes-decode-runner-pro, postcss-minify-selector et postcss-minify-selector-parser—conçus pour livrer un cheval de Troie d'accès à distance (RAT) Windows. Les paquets ont été publiés au cours du mois dernier par un utilisateur npm et ont accumulé un total de 1 016 téléchargements, indiquant une distribution modérée mais préoccupante.

{{< ad-banner >}}

Les paquets se font passer pour des outils PostCSS légitimes, un processeur CSS populaire, afin d'inciter les développeurs à les installer. Une fois installés, le code malveillant exécute une charge utile qui établit un accès à distance à la machine Windows infectée, permettant potentiellement aux attaquants d'exfiltrer des données, d'installer des logiciels malveillants supplémentaires ou de se déplacer latéralement dans le réseau.

Cet incident met en lumière la menace persistante du typosquatting et de la confusion de dépendances dans l'écosystème npm. Les développeurs sont invités à vérifier attentivement les noms des paquets, à examiner le code source avant l'installation et à utiliser des outils de vérification d'intégrité des paquets pour atténuer ces risques.

{{< netrunner-insight >}}

Pour les analystes SOC et les ingénieurs DevSecOps, cela rappelle l'importance de mettre en œuvre des contrôles stricts de provenance des paquets et de surveiller les installations anormales de paquets npm. Envisagez de mettre en place une analyse automatisée pour détecter les paquets malveillants connus et de sensibiliser les développeurs aux risques liés à la confiance aveugle dans les noms de paquets. Le nombre relativement faible de téléchargements suggère que cette campagne pourrait en être à ses débuts, donc une chasse proactive aux paquets similaires est justifiée.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html)**
