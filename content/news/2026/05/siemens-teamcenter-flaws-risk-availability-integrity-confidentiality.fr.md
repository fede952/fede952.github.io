---
title: "Les vulnérabilités de Siemens Teamcenter menacent la disponibilité, l'intégrité et la confidentialité"
date: "2026-05-16T08:47:33Z"
original_date: "2026-05-14T12:00:00"
lang: "fr"
translationKey: "siemens-teamcenter-flaws-risk-availability-integrity-confidentiality"
author: "NewsBot (Validated by Federico Sella)"
description: "De multiples vulnérabilités dans Siemens Teamcenter pourraient compromettre la disponibilité, l'intégrité et la confidentialité. Mettez à jour vers les dernières versions immédiatement."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04"
source: "CISA"
severity: "High"
target: "Siemens Teamcenter"
cve: "CVE-2024-4367"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

De multiples vulnérabilités dans Siemens Teamcenter pourraient compromettre la disponibilité, l'intégrité et la confidentialité. Mettez à jour vers les dernières versions immédiatement.

{{< cyber-report severity="High" source="CISA" target="Siemens Teamcenter" cve="CVE-2024-4367" cvss="7.5" >}}

Siemens Teamcenter est affecté par de multiples vulnérabilités qui pourraient entraîner une compromission de la disponibilité, de l'intégrité et de la confidentialité. Les failles incluent une vérification incorrecte des conditions inhabituelles ou exceptionnelles, du cross-site scripting et l'utilisation de mots de passe codés en dur. Les versions concernées incluent Teamcenter V2312, V2406, V2412, V2506 et V2512.

{{< ad-banner >}}

CVE-2024-4367 est un contrôle de type manquant lors du traitement des polices dans PDF.js, permettant l'exécution arbitraire de JavaScript dans le contexte de PDF.js. Cette vulnérabilité affecte Firefox et Thunderbird mais est répertoriée dans l'avis de Siemens. Siemens recommande de mettre à jour vers les dernières versions de Teamcenter pour atténuer ces risques.

Les vulnérabilités ont un score de base CVSS v3 de 7,5, indiquant une sévérité élevée. Les secteurs critiques de la fabrication sont affectés, avec un déploiement mondial. Les organisations doivent prioriser le correctif et examiner leur exposition à ces vulnérabilités.

{{< netrunner-insight >}}

Les analystes SOC doivent immédiatement inventorier toutes les instances Teamcenter et prioriser le correctif vers les dernières versions. Les équipes DevSecOps doivent vérifier que les composants PDF.js sont mis à jour et surveiller les tentatives d'exploitation ciblant ces CVE. Compte tenu du score CVSS élevé et du risque de compromission totale, traitez cela comme une correction hautement prioritaire.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04)**
