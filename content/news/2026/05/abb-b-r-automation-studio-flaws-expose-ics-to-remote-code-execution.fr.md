---
title: "Les failles d'ABB B&R Automation Studio exposent les ICS à une exécution de code à distance"
date: "2026-05-23T09:00:47Z"
original_date: "2026-05-21T12:00:00"
lang: "fr"
translationKey: "abb-b-r-automation-studio-flaws-expose-ics-to-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA met en garde contre 25 vulnérabilités dans ABB B&R Automation Studio, dont des bugs critiques CVSS 9,8 qui pourraient permettre un accès non autorisé et une exécution de code à distance."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03"
source: "CISA"
severity: "Critical"
target: "ABB B&R Automation Studio"
cve: "CVE-2025-6965"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA met en garde contre 25 vulnérabilités dans ABB B&R Automation Studio, dont des bugs critiques CVSS 9,8 qui pourraient permettre un accès non autorisé et une exécution de code à distance.

{{< cyber-report severity="Critical" source="CISA" target="ABB B&R Automation Studio" cve="CVE-2025-6965" cvss="9.8" >}}

CISA a publié un avis détaillant plusieurs vulnérabilités dans ABB B&R Automation Studio, affectant les versions antérieures à 6.5 et la version 6.5. L'avis répertorie 25 CVE, dont CVE-2025-6965, CVE-2025-3277 et CVE-2023-7104, entre autres. Ces vulnérabilités proviennent de composants tiers obsolètes et incluent des problèmes tels que des débordements de tampon basés sur le tas, des écritures hors limites, une utilisation après libération et une validation d'entrée incorrecte.

{{< ad-banner >}}

Bien qu'ABB ne signale aucune exploitation observée lors des tests, les vulnérabilités pourraient constituer des vecteurs d'attaque pour un accès non autorisé, une exposition de données ou une exécution de code à distance. Les CVE les plus graves ont un score CVSS v3 de 9,8, indiquant une sévérité critique. Les produits concernés sont utilisés dans les systèmes d'automatisation et de contrôle industriels, ce qui en fait des cibles attrayantes pour les acteurs malveillants.

ABB a publié une mise à jour qui remplace le composant tiers obsolète. Les organisations utilisant B&R Automation Studio sont invitées à appliquer la mise à jour immédiatement. Compte tenu de la nature critique de ces vulnérabilités et du potentiel d'exploitation à distance, les propriétaires d'actifs doivent prioriser le correctif et surveiller tout signe de compromission.

{{< netrunner-insight >}}

Pour les analystes SOC et les ingénieurs DevSecOps, cet avis souligne le risque des dépendances tierces dans les logiciels ICS. Le nombre élevé de CVE (25) suggère un problème systémique de gestion des composants. Priorisez l'inventaire des instances de B&R Automation Studio et appliquez la mise à jour du fournisseur. De plus, segmentez les réseaux ICS pour limiter l'exposition et mettez en place une surveillance des comportements anormaux qui pourraient indiquer des tentatives d'exploitation.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03)**
