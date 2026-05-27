---
title: "CISA met en garde contre des failles dans ABB Camera Connect via un composant VLC Media Player"
date: "2026-05-27T10:51:57Z"
original_date: "2026-05-26T12:00:00"
lang: "fr"
translationKey: "cisa-warns-of-abb-camera-connect-flaws-via-vlc-media-player-component"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB Ability Camera Connect versions ≤1.5.0.14 inclut un VLC media player 2.2.4 vulnérable avec plusieurs bugs de corruption mémoire, dont CVE-2024-46461, posant un risque critique."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05"
source: "CISA"
severity: "Critical"
target: "ABB Ability Camera Connect"
cve: "CVE-2024-46461"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB Ability Camera Connect versions ≤1.5.0.14 inclut un VLC media player 2.2.4 vulnérable avec plusieurs bugs de corruption mémoire, dont CVE-2024-46461, posant un risque critique.

{{< cyber-report severity="Critical" source="CISA" target="ABB Ability Camera Connect" cve="CVE-2024-46461" cvss="9.8" >}}

CISA a publié un avis (ICSA-26-146-05) détaillant plusieurs vulnérabilités dans ABB Ability Camera Connect versions 1.5.0.14 et antérieures. Les failles proviennent d'un composant tiers obsolète, VLC media player version 2.2.4, qui est intégré au package d'installation. Une mise à jour vers la version 1.5.0.15 résout le problème en remplaçant le composant vulnérable.

{{< ad-banner >}}

Les vulnérabilités incluent un débordement de tampon basé sur le tas, un sous-dépassement d'entier, une écriture hors limites, un élément de chemin de recherche non contrôlé, un dépassement d'entier, une erreur de décalage d'un, une lecture hors limites, une double libération, une restriction incorrecte des opérations dans les tampons mémoire, et une utilisation après libération. Notamment, CVE-2024-46461 décrit un débordement basé sur le tas dans VLC media player 3.0.20 et antérieur via un flux MMS malveillant, conduisant à un déni de service.

Avec un score CVSS v3 de 9,8, ces vulnérabilités sont classées comme critiques. Les secteurs d'infrastructures critiques concernés incluent la chimie, les installations commerciales, les communications, la fabrication critique, l'énergie et les systèmes de transport. Le produit est déployé dans le monde entier, et l'exploitation pourrait permettre à un attaquant de compromettre le système de diverses manières.

{{< netrunner-insight >}}

Cet avis souligne le risque de vulnérabilités héritées de composants tiers. Les analystes SOC devraient prioriser le correctif d'ABB Ability Camera Connect vers la version 1.5.0.15 et surveiller les tentatives d'exploitation ciblant les failles de VLC media player. Les équipes DevSecOps doivent imposer un contrôle strict des versions de composants et une analyse régulière des bibliothèques intégrées.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05)**
