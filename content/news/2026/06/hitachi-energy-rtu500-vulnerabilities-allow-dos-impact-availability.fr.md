---
title: "Les vulnérabilités du RTU500 de Hitachi Energy permettent des dénis de service et impactent la disponibilité"
date: "2026-06-05T10:46:09Z"
original_date: "2026-06-04T12:00:00"
lang: "fr"
translationKey: "hitachi-energy-rtu500-vulnerabilities-allow-dos-impact-availability"
author: "NewsBot (Validated by Federico Sella)"
description: "La CISA met en garde contre de multiples vulnérabilités dans la série RTU500 de Hitachi Energy, notamment un déréférencement de pointeur NULL et une boucle infinie, avec un score CVSS de 7,8. Les versions concernées sont listées."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04"
source: "CISA"
severity: "High"
target: "Firmware CMU de la série RTU500 de Hitachi Energy"
cve: "CVE-2025-69421"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

La CISA met en garde contre de multiples vulnérabilités dans la série RTU500 de Hitachi Energy, notamment un déréférencement de pointeur NULL et une boucle infinie, avec un score CVSS de 7,8. Les versions concernées sont listées.

{{< cyber-report severity="High" source="CISA" target="Firmware CMU de la série RTU500 de Hitachi Energy" cve="CVE-2025-69421" cvss="7.8" >}}

Hitachi Energy a divulgué de multiples vulnérabilités affectant le firmware CMU de sa série RTU500. Les failles incluent un déréférencement de pointeur NULL, un débordement d'entier ou un enroulement, et une boucle sans condition de sortie (boucle infinie), ce qui pourrait entraîner des conditions de déni de service. L'exploitation impacte principalement la disponibilité du produit, avec des effets secondaires potentiels sur la confidentialité et l'intégrité.

{{< ad-banner >}}

L'avis, publié par la CISA (ICSA-26-155-04), liste les versions de firmware concernées allant de 12.7.1 à 13.8.1. Plusieurs CVE sont associées, notamment CVE-2025-69421, CVE-2026-24515, CVE-2026-25210, CVE-2026-32776, CVE-2026-32777, CVE-2026-32778 et CVE-2026-8479. Les vulnérabilités ont un score de base CVSS v3 de 7,8, indiquant une sévérité élevée.

Hitachi Energy recommande une action immédiate conformément aux conseils de correction de l'avis. Compte tenu du contexte des infrastructures critiques, les organisations utilisant des versions RTU500 concernées devraient prioriser le patching et mettre en œuvre une segmentation réseau pour atténuer le risque d'exploitation.

{{< netrunner-insight >}}

Ces vulnérabilités rappellent que les appareils OT accusent souvent un retard dans les cycles de correctifs. Les équipes SOC doivent surveiller le trafic anormal vers les unités RTU500 et s'assurer que ces appareils sont isolés des réseaux non fiables. Les ingénieurs DevSecOps devraient intégrer l'analyse du firmware dans les pipelines CI/CD pour détecter les CVE connues avant le déploiement.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04)**
