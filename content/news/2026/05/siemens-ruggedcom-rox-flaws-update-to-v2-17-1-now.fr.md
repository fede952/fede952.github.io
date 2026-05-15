---
title: "Vulnérabilités Siemens Ruggedcom ROX : Mettez à jour vers la v2.17.1 maintenant"
date: "2026-05-15T09:41:40Z"
original_date: "2026-05-14T12:00:00"
lang: "fr"
translationKey: "siemens-ruggedcom-rox-flaws-update-to-v2-17-1-now"
author: "NewsBot (Validated by Federico Sella)"
description: "La CISA met en garde contre de multiples vulnérabilités de tiers dans Siemens Ruggedcom ROX avant la v2.17.1. Plus de 30 CVE listées, incluant des risques d'exécution de code à distance. Mise à jour immédiate recommandée."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16"
source: "CISA"
severity: "High"
target: "Dispositifs Siemens Ruggedcom ROX"
cve: "CVE-2019-13103"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

La CISA met en garde contre de multiples vulnérabilités de tiers dans Siemens Ruggedcom ROX avant la v2.17.1. Plus de 30 CVE listées, incluant des risques d'exécution de code à distance. Mise à jour immédiate recommandée.

{{< cyber-report severity="High" source="CISA" target="Dispositifs Siemens Ruggedcom ROX" cve="CVE-2019-13103" >}}

Les versions de Siemens Ruggedcom ROX antérieures à 2.17.1 contiennent de multiples vulnérabilités de tiers, comme divulgué dans l'avis CISA ICSA-26-134-16. Les produits concernés incluent les séries RUGGEDCOM ROX MX5000, MX5000RE et RX1400. Siemens a publié des versions mises à jour pour corriger ces problèmes et recommande vivement de passer à la dernière version.

{{< ad-banner >}}

L'avis liste plus de 30 CVE allant de 2019 à 2025, dont CVE-2019-13103, CVE-2022-2347 et CVE-2025-0395. Bien qu'aucun score CVSS spécifique ne soit fourni, l'étendue et l'ancienneté des vulnérabilités suggèrent une surface d'attaque significative. Beaucoup de ces CVE sont associées à des composants tiers et pourraient conduire à une exécution de code à distance, un déni de service ou une divulgation d'informations.

Les organisations utilisant des dispositifs Ruggedcom ROX affectés devraient prioriser le déploiement de correctifs, surtout si les appareils sont exposés à des réseaux non fiables. Compte tenu de la nature industrielle de ces produits, les systèmes non corrigés pourraient être exploités pour des mouvements latéraux ou la perturbation d'infrastructures critiques.

{{< netrunner-insight >}}

C'est un cas classique de dette technique accumulée dans les systèmes embarqués. Les analystes SOC doivent inventorier toutes les instances Ruggedcom ROX et vérifier les versions de firmware. Les équipes DevSecOps doivent intégrer le scan automatisé des CVE dans leur CI/CD pour les dépendances tierces. L'absence de scores CVSS est préoccupante—partez du pire scénario et traitez-les comme critiques jusqu'à preuve du contraire.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16)**
