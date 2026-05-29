---
title: "CISA met en garde contre les vulnérabilités d'ABB EIBPORT permettant l'accès aux données et la modification de la configuration"
date: "2026-05-29T10:43:33Z"
original_date: "2026-05-28T12:00:00"
lang: "fr"
translationKey: "cisa-warns-of-abb-eibport-vulnerabilities-allowing-data-access-and-config-changes"
author: "NewsBot (Validated by Federico Sella)"
description: "Les appareils ABB EIBPORT sont vulnérables au cross-site scripting et au vol d'ID de session. Une mise à jour du firmware vers la version 3.9.2 est disponible."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03"
source: "CISA"
severity: "High"
target: "Appareils ABB EIBPORT"
cve: "CVE-2021-22291"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Les appareils ABB EIBPORT sont vulnérables au cross-site scripting et au vol d'ID de session. Une mise à jour du firmware vers la version 3.9.2 est disponible.

{{< cyber-report severity="High" source="CISA" target="Appareils ABB EIBPORT" cve="CVE-2021-22291" >}}

La CISA a publié un avis (ICSA-26-148-03) détaillant plusieurs vulnérabilités dans les appareils ABB EIBPORT, notamment les modèles EIBPORT V3 KNX et EIBPORT V3 KNX GSM. Les vulnérabilités, qui incluent une faille de cross-site scripting (XSS) (CWE-79) et un problème de vol d'ID de session (CVE-2021-22291), pourraient permettre à un attaquant d'accéder à des informations sensibles stockées sur l'appareil et de modifier sa configuration.

{{< ad-banner >}}

Les versions de firmware concernées sont celles antérieures à 3.9.2. ABB a publié une mise à jour du firmware pour corriger ces vulnérabilités signalées de manière privée. Les produits sont déployés dans le monde entier dans les secteurs de la fabrication critique et des technologies de l'information, le fournisseur étant basé en Suisse.

Bien qu'aucun score CVSS ne soit fourni dans l'avis, l'impact potentiel sur l'intégrité et la confidentialité de l'appareil justifie une correction rapide. Les organisations utilisant des appareils ABB EIBPORT concernés doivent appliquer la mise à jour du firmware dès que possible pour atténuer le risque d'exploitation.

{{< netrunner-insight >}}

Pour les analystes SOC, priorisez la recherche d'appareils ABB EIBPORT exécutant un firmware inférieur à 3.9.2 et surveillez les modifications de configuration anormales ou les anomalies de session. Les équipes DevSecOps doivent intégrer cette mise à jour du firmware dans leur pipeline de gestion des correctifs, surtout compte tenu du rôle de l'appareil dans l'automatisation des bâtiments et les infrastructures critiques.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03)**
