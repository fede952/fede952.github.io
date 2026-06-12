---
title: "CISA met en garde contre des vulnérabilités critiques de l'IoT Naxclow permettant la prise de contrôle des appareils"
date: "2026-06-12T10:59:58Z"
original_date: "2026-06-11T12:00:00"
lang: "fr"
translationKey: "cisa-warns-of-critical-naxclow-iot-flaws-allowing-device-takeover"
author: "NewsBot (Validated by Federico Sella)"
description: "Plusieurs vulnérabilités dans la plateforme IoT Naxclow, dont CVE-2026-42947, permettent le détournement d'appareils et la récolte d'identifiants. Cela affecte les sonnettes intelligentes et les hubs domestiques."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02"
source: "CISA"
severity: "Critical"
target: "Appareils de la plateforme IoT Naxclow"
cve: "CVE-2026-42947"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Plusieurs vulnérabilités dans la plateforme IoT Naxclow, dont CVE-2026-42947, permettent le détournement d'appareils et la récolte d'identifiants. Cela affecte les sonnettes intelligentes et les hubs domestiques.

{{< cyber-report severity="Critical" source="CISA" target="Appareils de la plateforme IoT Naxclow" cve="CVE-2026-42947" cvss="9.8" >}}

CISA a publié un avis (ICSA-26-162-02) détaillant plusieurs vulnérabilités dans la plateforme IoT Naxclow, affectant des produits tels que Smart Doorbell X3, X Smart Home, V720 et ix cam. La faille la plus grave, CVE-2026-42947, a un score CVSS de 9,8 et implique un contournement d'autorisation via une clé contrôlée par l'utilisateur, permettant à un attaquant de rejouer une séquence de confirmation puis de liaison pour réaffecter silencieusement un appareil à un compte arbitraire sans interaction de l'utilisateur.

{{< ad-banner >}}

Les faiblesses supplémentaires incluent l'absence de vérifications d'autorisation, l'utilisation de clés cryptographiques codées en dur, la génération d'identifiants prévisibles et l'insertion d'informations sensibles dans des fichiers accessibles de l'extérieur. Une exploitation réussie pourrait permettre l'usurpation d'identité d'appareils, l'interception ou la manipulation de communications, la récolte à grande échelle d'identifiants et un accès non autorisé aux systèmes affectés.

Les vulnérabilités affectent toutes les versions des produits listés, et les appareils sont déployés dans le monde entier dans des installations commerciales. Naxclow, dont le siège est en Chine, n'a pas encore publié de correctifs. Les organisations utilisant ces appareils doivent immédiatement mettre en œuvre la segmentation du réseau et la surveillance pour détecter les activités de liaison anormales.

{{< netrunner-insight >}}

C'est un cauchemar IoT de chaîne d'approvisionnement classique : clés codées en dur, identifiants prévisibles et un processus d'intégration rejouable. Les équipes SOC doivent rechercher des réaffectations inattendues d'appareils dans les journaux et envisager d'isoler les appareils Naxclow sur un VLAN séparé jusqu'à l'arrivée des correctifs. DevSecOps doit pousser pour une identité cryptographique des appareils et une authentification mutuelle dans l'intégration IoT.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02)**
