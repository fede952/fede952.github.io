---
title: "Près de 800 paquets npm malveillants distribuent un RAT multiplateforme et un voleur d'informations"
date: "2026-08-08T07:43:01Z"
original_date: "2026-08-07T18:48:17"
lang: "fr"
translationKey: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
slug: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
author: "NewsBot (Validated by Federico Sella)"
description: "Une campagne de près de 800 paquets npm malveillants utilise des typosquattages générés par IA pour distribuer un RAT multiplateforme et un voleur d'informations ciblant Windows, Mac et Linux."
original_url: "https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "utilisateurs du registre npm"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Une campagne de près de 800 paquets npm malveillants utilise des typosquattages générés par IA pour distribuer un RAT multiplateforme et un voleur d'informations ciblant Windows, Mac et Linux.

{{< cyber-report severity="High" source="The Hacker News" target="utilisateurs du registre npm" >}}

Une nouvelle campagne a été découverte, publiant près de 800 paquets malveillants sur le registre npm, selon un rapport du chercheur Paul d'OpenSourceMalware. Les paquets sont conçus pour distribuer un cheval de Troie d'accès à distance (RAT) multiplateforme et une charge utile de voleur d'informations, affectant les systèmes Windows, macOS et Linux.

{{< ad-banner >}}

Les paquets malveillants semblent utiliser des noms de paquets 'typosquattés par IA' ou générés aléatoirement, une technique qui exploite des noms générés par IA pour échapper à la détection et tromper les développeurs afin qu'ils les installent. Une fois installés, la charge utile fournit aux attaquants un accès à distance et la capacité de voler des informations sensibles des systèmes compromis.

Cette campagne met en évidence le risque continu des attaques de la chaîne d'approvisionnement via les registres de paquets. Les développeurs et les organisations sont invités à examiner attentivement les noms de paquets, à vérifier les identités des éditeurs et à utiliser des analyses de sécurité automatisées pour détecter et bloquer ces paquets malveillants avant qu'ils ne puissent causer des dommages.

{{< netrunner-insight >}}

Pour les analystes SOC et les ingénieurs DevSecOps, cette campagne souligne la nécessité d'une vérification robuste de la provenance des paquets et d'une surveillance en temps réel. Mettez en œuvre des outils automatisés qui signalent les noms et comportements suspects de paquets, et envisagez d'utiliser un registre privé avec une liste blanche stricte. De plus, sensibilisez les développeurs aux risques du typosquattage et encouragez-les à vérifier deux fois les noms de paquets avant l'installation.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html)**
