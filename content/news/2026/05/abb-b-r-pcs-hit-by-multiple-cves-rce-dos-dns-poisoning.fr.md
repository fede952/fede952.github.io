---
title: "PC industriels ABB B&R touchés par de multiples CVE : exécution de code à distance, déni de service, empoisonnement DNS"
date: "2026-05-22T10:21:58Z"
original_date: "2026-05-21T12:00:00"
lang: "fr"
translationKey: "abb-b-r-pcs-hit-by-multiple-cves-rce-dos-dns-poisoning"
author: "NewsBot (Validated by Federico Sella)"
description: "La CISA met en garde contre des vulnérabilités dans les PC industriels ABB B&R. Une mise à jour est disponible. Les attaquants peuvent exécuter du code à distance, provoquer un déni de service, empoisonner le cache DNS ou voler des données."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02"
source: "CISA"
severity: "High"
target: "PC industriels ABB B&R"
cve: "CVE-2023-45229"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

La CISA met en garde contre des vulnérabilités dans les PC industriels ABB B&R. Une mise à jour est disponible. Les attaquants peuvent exécuter du code à distance, provoquer un déni de service, empoisonner le cache DNS ou voler des données.

{{< cyber-report severity="High" source="CISA" target="PC industriels ABB B&R" cve="CVE-2023-45229" >}}

ABB a divulgué des vulnérabilités affectant plusieurs gammes de PC industriels B&R, notamment APC4100, APC910, C80, MPC3100, PPC1200, PPC900 et APC2200. Les failles, référencées CVE-2023-45229 à CVE-2023-45237, permettent à des attaquants réseau d'exécuter du code à distance, de lancer des attaques par déni de service, d'empoisonner les caches DNS ou d'extraire des informations sensibles.

{{< ad-banner >}}

L'avis liste les versions affectées pour chaque produit, avec des mises à jour disponibles pour corriger les problèmes. Par exemple, les versions d'APC4100 antérieures à 1.09 sont vulnérables, tandis que la version 1.09 est corrigée. De même, les versions d'APC910 jusqu'à 1.25 inclus sont concernées. ABB recommande de mettre à jour immédiatement vers les dernières versions du firmware.

Compte tenu du contexte des systèmes de contrôle industriels (ICS), ces vulnérabilités présentent des risques significatifs pour les environnements de technologies opérationnelles. Les organisations utilisant des PC ABB B&R affectés devraient prioriser le déploiement des correctifs, surtout si les appareils sont exposés à des réseaux non fiables.

{{< netrunner-insight >}}

Pour les analystes SOC, surveillez le trafic réseau pour détecter des requêtes DNS anormales ou des connexions inattendues provenant des PC B&R. Les équipes DevSecOps doivent inventorier tous les appareils concernés et appliquer les mises à jour du firmware dès que possible, car ces CVE permettent une exécution de code à distance sans authentification. Envisagez de segmenter les réseaux ICS pour limiter l'exposition.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02)**
