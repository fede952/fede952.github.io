---
title: "Hitachi Energy ITT600 Explorer vulnérable à un déni de service via des failles libexpat"
date: "2026-06-05T10:44:09Z"
original_date: "2026-06-04T12:00:00"
lang: "fr"
translationKey: "hitachi-energy-itt600-explorer-vulnerable-to-dos-via-libexpat-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA met en garde contre deux vulnérabilités dans Hitachi Energy ITT600 Explorer qui pourraient permettre des attaques par déni de service. Affecte les versions antérieures à 2.1 SP6."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02"
source: "CISA"
severity: "High"
target: "Hitachi Energy ITT600 Explorer"
cve: "CVE-2024-8176"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA met en garde contre deux vulnérabilités dans Hitachi Energy ITT600 Explorer qui pourraient permettre des attaques par déni de service. Affecte les versions antérieures à 2.1 SP6.

{{< cyber-report severity="High" source="CISA" target="Hitachi Energy ITT600 Explorer" cve="CVE-2024-8176" cvss="7.5" >}}

Hitachi Energy a divulgué des vulnérabilités dans son produit ITT600 Explorer, affectant spécifiquement les versions antérieures à 2.1 SP6. Les failles, identifiées comme CVE-2024-8176 et CVE-2025-59375, impliquent une récursion non contrôlée et une allocation de ressources sans limites ou limitation. Ces problèmes peuvent être exploités pour provoquer une condition de déni de service (DoS).

{{< ad-banner >}}

Les vulnérabilités résident dans la bibliothèque libexpat utilisée par la fonctionnalité IEC61850. Un attaquant ayant un accès local pourrait envoyer un message IEC61850 conçu pour déclencher un débordement de pile, pouvant entraîner une corruption de la mémoire en plus du DoS. Il est important de noter que seul le produit ITT600 Explorer est affecté ; les points d'extrémité du système IEC 61850 restent non affectés.

CISA recommande une action immédiate pour appliquer des mesures d'atténuation ou des mises à jour. Le produit est déployé dans le monde entier dans le secteur de l'énergie, et son exploitation pourrait perturber les opérations d'infrastructures critiques. Les organisations utilisant des versions affectées devraient prioriser le patching et consulter l'avis pour des étapes de remédiation détaillées.

{{< netrunner-insight >}}

Pour les analystes SOC, surveillez les schémas de trafic IEC61850 inhabituels qui pourraient indiquer des tentatives d'exploitation. Les équipes DevSecOps devraient prioriser la mise à jour d'ITT600 Explorer vers la version 2.1 SP6 ou ultérieure, et envisager une segmentation réseau pour limiter l'accès local à l'outil. Compte tenu du score CVSS de 7,5 et du risque de corruption mémoire, traitez cela comme un correctif haute priorité.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02)**
