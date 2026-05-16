---
title: "Les failles d'analyse de fichiers PAR dans Siemens Solid Edge permettent l'exécution de code"
date: "2026-05-16T08:48:36Z"
original_date: "2026-05-14T12:00:00"
lang: "fr"
translationKey: "siemens-solid-edge-par-parsing-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "Deux vulnérabilités d'analyse de fichiers dans Siemens Solid Edge SE2026 permettent à des attaquants d'exécuter du code arbitraire via des fichiers PAR spécialement conçus. Mettez à jour vers V226.0 Update 5."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03"
source: "CISA"
severity: "High"
target: "Siemens Solid Edge SE2026"
cve: "CVE-2026-44411"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Deux vulnérabilités d'analyse de fichiers dans Siemens Solid Edge SE2026 permettent à des attaquants d'exécuter du code arbitraire via des fichiers PAR spécialement conçus. Mettez à jour vers V226.0 Update 5.

{{< cyber-report severity="High" source="CISA" target="Siemens Solid Edge SE2026" cve="CVE-2026-44411" cvss="7.8" >}}

Siemens Solid Edge SE2026 avant Update 5 est affecté par deux vulnérabilités d'analyse de fichiers qui peuvent être déclenchées lorsque l'application lit des fichiers PAR spécialement conçus. Les failles incluent un accès à un pointeur non initialisé (CVE-2026-44411) et un débordement de tampon basé sur la pile (CVE-2026-44412), qui pourraient tous deux permettre à un attaquant de faire planter l'application ou d'exécuter du code arbitraire dans le contexte du processus en cours.

{{< ad-banner >}}

Les vulnérabilités ont un score de base CVSS v3.1 de 7.8 (High) avec le vecteur AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H, indiquant un accès local, une faible complexité, aucun privilège requis, une interaction utilisateur nécessaire et un impact élevé sur la confidentialité, l'intégrité et la disponibilité. Siemens a publié la version V226.0 Update 5 pour corriger ces problèmes et recommande aux utilisateurs de mettre à jour immédiatement.

Compte tenu du déploiement mondial dans le secteur de la fabrication critique, les organisations utilisant Solid Edge devraient prioriser le correctif. Les vulnérabilités nécessitent une interaction utilisateur (ouverture d'un fichier PAR malveillant), donc une formation de sensibilisation des utilisateurs est également recommandée comme mesure compensatoire.

{{< netrunner-insight >}}

Pour les analystes SOC, surveillez les traitements de fichiers PAR inhabituels ou les plantages dans les processus Solid Edge. Les ingénieurs DevSecOps doivent appliquer la liste blanche des applications et restreindre les types de fichiers pour réduire la surface d'attaque. Comme il s'agit de vulnérabilités locales dépendantes de l'interaction utilisateur, les simulations de phishing et les règles de détection des points de terminaison pour les ouvertures de fichiers suspects sont des mesures d'atténuation clés.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03)**
