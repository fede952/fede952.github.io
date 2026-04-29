---
title: "Vulnérabilités des caméras Milesight permettant l'exécution de code à distance"
date: "2026-04-29T07:21:59Z"
original_date: "2026-04-23T12:00:00"
lang: "fr"
translationKey: "milesight-camera-vulnerabilities-enable-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "La CISA met en garde contre plusieurs modèles de caméras Milesight affectés par des vulnérabilités critiques (CVE-2026-28747, etc.) pouvant entraîner un crash de l'appareil ou une exécution de code à distance."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03"
source: "CISA"
severity: "Critical"
target: "Caméras IP Milesight"
cve: "CVE-2026-28747"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

La CISA met en garde contre plusieurs modèles de caméras Milesight affectés par des vulnérabilités critiques (CVE-2026-28747, etc.) pouvant entraîner un crash de l'appareil ou une exécution de code à distance.

{{< cyber-report severity="Critical" source="CISA" target="Caméras IP Milesight" cve="CVE-2026-28747" >}}

La CISA a publié un avis (ICSA-26-113-03) détaillant plusieurs vulnérabilités affectant une large gamme de modèles de caméras Milesight. Les failles, identifiées sous les références CVE-2026-28747, CVE-2026-27785, CVE-2026-32644, CVE-2026-32649 et CVE-2026-20766, impactent les versions de firmware de plusieurs gammes de produits, notamment MS-Cxx63-PD, MS-Cxx64-xPD et autres. Une exploitation réussie pourrait permettre à un attaquant de faire planter l'appareil ou d'exécuter du code à distance.

{{< ad-banner >}}

Les modèles concernés couvrent plusieurs séries, avec des versions de firmware allant jusqu'à 51.7.0.77-r12, 3x.8.0.3-r11, 63.8.0.4-r3 et autres. Compte tenu de la nature critique de l'exécution de code à distance, ces vulnérabilités représentent un risque significatif pour les organisations utilisant des caméras Milesight dans des déploiements de surveillance ou IoT. La CISA recommande aux utilisateurs d'appliquer les correctifs disponibles et de suivre les directives du fabricant pour atténuer l'exposition.

Bien qu'aucun score CVSS ni preuve d'exploitation active ne soient fournis dans l'avis, le potentiel de compromission de l'appareil et d'intrusion réseau mérite une attention immédiate. Les équipes de sécurité doivent inventorier les modèles de caméras affectés, segmenter les appareils IoT des réseaux critiques et prioriser les mises à jour du firmware.

{{< netrunner-insight >}}

Pour les analystes SOC, surveillez le trafic anormal provenant des sous-réseaux de caméras et assurez-vous que ces appareils sont isolés. Les ingénieurs DevSecOps doivent accélérer le déploiement des correctifs sur toutes les caméras Milesight, car les vulnérabilités d'exécution de code à distance sur les périphériques de périphérie deviennent souvent des points d'entrée pour les mouvements latéraux. Traitez ces CVE comme critiques jusqu'à ce que les correctifs du fabricant soient vérifiés.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03)**
