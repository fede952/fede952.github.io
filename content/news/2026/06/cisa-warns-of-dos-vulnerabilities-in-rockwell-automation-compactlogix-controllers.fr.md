---
title: "CISA met en garde contre des vulnérabilités DoS dans les contrôleurs Rockwell Automation CompactLogix"
date: "2026-06-17T11:46:16Z"
original_date: "2026-06-16T12:00:00"
lang: "fr"
translationKey: "cisa-warns-of-dos-vulnerabilities-in-rockwell-automation-compactlogix-controllers"
author: "NewsBot (Validated by Federico Sella)"
description: "Plusieurs vulnérabilités dans les contrôleurs Rockwell Automation CompactLogix 5370 pourraient permettre des attaques par déni de service. CVE-2025-11694 fait partie des failles."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04"
source: "CISA"
severity: "High"
target: "Contrôleurs Rockwell Automation CompactLogix 5370"
cve: "CVE-2025-11694"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Plusieurs vulnérabilités dans les contrôleurs Rockwell Automation CompactLogix 5370 pourraient permettre des attaques par déni de service. CVE-2025-11694 fait partie des failles.

{{< cyber-report severity="High" source="CISA" target="Contrôleurs Rockwell Automation CompactLogix 5370" cve="CVE-2025-11694" cvss="7.5" >}}

La CISA a publié un avis (ICSA-26-167-04) détaillant des vulnérabilités dans les contrôleurs Rockwell Automation CompactLogix 5370 (L1, L2, L3). Les failles incluent une validation incorrecte des valeurs de contrôle d'intégrité et l'exposition d'informations système sensibles, ce qui pourrait permettre à un attaquant de provoquer un déni de service. L'avis concerne les versions antérieures à V38.011.

{{< ad-banner >}}

La vulnérabilité la plus notable, CVE-2025-11694, implique un manque de validation des numéros de séquence et des adresses IP source dans le protocole CIP. Un attaquant peut exploiter les identifiants de connexion exposés sur l'interface web pour mener des attaques par déni de service, entraînant une panne mineure. Le score CVSS v3 pour cette vulnérabilité est de 7,5.

Rockwell Automation recommande de mettre à jour vers la version V38.011 pour corriger ces problèmes. Les produits concernés sont déployés dans le monde entier dans le secteur de la fabrication critique. Les organisations devraient prioriser le correctif de ces contrôleurs pour atténuer les perturbations opérationnelles potentielles.

{{< netrunner-insight >}}

Pour les analystes SOC, surveillez les schémas de trafic CIP inhabituels ou les tentatives de connexion répétées ciblant les contrôleurs CompactLogix. Les ingénieurs DevSecOps doivent s'assurer que l'interface web n'est pas exposée à des réseaux non fiables et appliquer la mise à jour du firmware vers V38.011 rapidement. Il s'agit d'un vecteur DoS simple qui peut être atténué par une segmentation réseau appropriée et une gestion des correctifs.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04)**
