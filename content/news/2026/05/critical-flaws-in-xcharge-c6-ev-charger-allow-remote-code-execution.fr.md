---
title: "Vulnérabilités critiques dans le chargeur EV XCharge C6 permettant l'exécution de code à distance"
date: "2026-05-29T10:39:44Z"
original_date: "2026-05-28T12:00:00"
lang: "fr"
translationKey: "critical-flaws-in-xcharge-c6-ev-charger-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA met en garde contre des vulnérabilités non authentifiées dans les contrôleurs de charge EV XCharge C6, dont CVE-2026-9037, avec un score CVSS de 9,8."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08"
source: "CISA"
severity: "Critical"
target: "Contrôleurs de charge EV XCharge C6"
cve: "CVE-2026-9037"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA met en garde contre des vulnérabilités non authentifiées dans les contrôleurs de charge EV XCharge C6, dont CVE-2026-9037, avec un score CVSS de 9,8.

{{< cyber-report severity="Critical" source="CISA" target="Contrôleurs de charge EV XCharge C6" cve="CVE-2026-9037" cvss="9.8" >}}

CISA a publié un avis (ICSA-26-148-08) détaillant plusieurs vulnérabilités critiques dans les contrôleurs de charge pour véhicules électriques XCharge C6. Les failles incluent un téléchargement de code sans vérification d'intégrité (CWE-494), un débordement de tampon basé sur la pile, et une initialisation d'une ressource avec une valeur par défaut non sécurisée. Une exploitation réussie pourrait permettre à un attaquant d'obtenir des droits d'administrateur ou d'exécuter du code arbitraire sur l'appareil.

{{< ad-banner >}}

La vulnérabilité la plus grave, CVE-2026-9037, concerne un mécanisme de mise à jour du firmware qui ne valide pas l'authenticité des paquets de firmware. Sans vérification de signature cryptographique, un attaquant capable d'interférer avec ou d'usurper le canal de gestion pourrait installer un firmware non autorisé, conduisant à une exécution de code à privilèges élevés. Le score CVSS v3 de cette vulnérabilité est de 9,8, indiquant une sévérité critique.

XCharge a déployé une mise à jour du firmware pour tous les chargeurs concernés à compter du 22 mai 2026. Les utilisateurs sont invités à s'assurer que leurs appareils sont mis à jour et à contacter le support XCharge si nécessaire. Le produit concerné est largement déployé dans le secteur des systèmes de transport dans plusieurs pays.

{{< netrunner-insight >}}

Pour les analystes SOC, priorisez la surveillance des interfaces de gestion des chargeurs XCharge C6 pour détecter tout accès non autorisé ou toute demande de mise à jour du firmware anormale. Les équipes DevSecOps doivent imposer une segmentation réseau et appliquer immédiatement le correctif du fournisseur, car l'absence de vérifications d'intégrité fait de ces appareils une cible de choix pour les attaques sur la chaîne d'approvisionnement.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08)**
