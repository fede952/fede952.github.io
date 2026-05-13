---
title: "Les failles de Subnet Solutions PowerSYSTEM Center permettent une fuite d'informations et une injection CRLF"
date: "2026-05-13T09:40:06Z"
original_date: "2026-05-12T12:00:00"
lang: "fr"
translationKey: "subnet-solutions-powersystem-center-flaws-enable-info-leak-crlf-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA met en garde contre de multiples vulnérabilités dans Subnet Solutions PowerSYSTEM Center, notamment la divulgation d'informations et l'injection CRLF, affectant les versions de 2020 à 2026."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02"
source: "CISA"
severity: "High"
target: "Subnet Solutions PowerSYSTEM Center"
cve: "CVE-2026-35504"
cvss: 8.2
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA met en garde contre de multiples vulnérabilités dans Subnet Solutions PowerSYSTEM Center, notamment la divulgation d'informations et l'injection CRLF, affectant les versions de 2020 à 2026.

{{< cyber-report severity="High" source="CISA" target="Subnet Solutions PowerSYSTEM Center" cve="CVE-2026-35504" cvss="8.2" >}}

CISA a publié un avis (ICSA-26-132-02) détaillant plusieurs vulnérabilités dans Subnet Solutions PowerSYSTEM Center, une plateforme utilisée dans les secteurs critiques de la fabrication et de l'énergie. Les failles incluent une autorisation incorrecte (CVE-2026-26289) qui permet à des utilisateurs authentifiés disposant de permissions limitées d'exporter des comptes d'appareils et d'exposer des informations sensibles normalement réservées aux administrateurs. De plus, des vulnérabilités d'injection CRLF (CVE-2026-35504, CVE-2026-33570, CVE-2026-35555) pourraient permettre à des attaquants d'injecter des en-têtes ou des réponses malveillants.

{{< ad-banner >}}

Les versions concernées couvrent PowerSYSTEM Center 2020 (5.8.x à 5.28.x), 2024 (6.0.x à 6.1.x) et 2026 (7.0.x). Les vulnérabilités ont un score de base CVSS v3 de 8,2, indiquant une sévérité élevée. Une exploitation réussie pourrait entraîner une divulgation d'informations et une manipulation potentielle des sessions ou un fractionnement des réponses HTTP.

Compte tenu du déploiement du produit dans des infrastructures critiques dans le monde entier, les organisations devraient prioriser le déploiement de correctifs. Subnet Solutions a probablement publié des mises à jour ; les administrateurs sont invités à consulter les avis de sécurité du fournisseur et à appliquer les derniers correctifs. En attendant, restreignez l'accès réseau à PowerSYSTEM Center et surveillez les activités anormales.

{{< netrunner-insight >}}

Pour les analystes SOC, surveillez les journaux d'authentification pour détecter des exportations inhabituelles de comptes d'appareils—c'est un signe révélateur de l'exploitation de CVE-2026-26289. Les équipes DevSecOps doivent immédiatement inventorier les versions de PowerSYSTEM Center et appliquer les correctifs, car les vecteurs d'injection CRLF (CVE-2026-35504 et al.) pourraient être chaînés avec d'autres attaques pour compromettre l'intégrité des sessions. Traitez cela comme une correction hautement prioritaire compte tenu du score CVSS 8,2 et de l'exposition dans des secteurs critiques.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02)**
