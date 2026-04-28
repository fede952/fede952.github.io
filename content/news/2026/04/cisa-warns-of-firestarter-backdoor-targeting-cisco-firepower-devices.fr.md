---
title: "CISA met en garde contre la porte dérobée FIRESTARTER ciblant les appareils Cisco Firepower"
date: "2026-04-23T12:00:00"
lang: "fr"
translationKey: "cisa-warns-of-firestarter-backdoor-targeting-cisco-firepower-devices"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA et NCSC alertent sur des acteurs APT utilisant la porte dérobée FIRESTARTER pour la persistance sur les appareils Cisco ASA/FTD. Des mesures d'urgence sont décrites."
original_url: "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"
source: "CISA"
severity: "High"
target: "Appareils Cisco Firepower et Secure Firewall"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA et NCSC alertent sur des acteurs APT utilisant la porte dérobée FIRESTARTER pour la persistance sur les appareils Cisco ASA/FTD. Des mesures d'urgence sont décrites.

{{< cyber-report severity="High" source="CISA" target="Appareils Cisco Firepower et Secure Firewall" >}}

CISA et le NCSC britannique ont publié un rapport d'analyse de malware sur la porte dérobée FIRESTARTER, utilisée par des acteurs de menace persistante avancée (APT) pour maintenir la persistance sur des appareils Cisco Firepower et Secure Firewall accessibles publiquement exécutant les logiciels ASA ou FTD. L'analyse est basée sur un échantillon obtenu lors d'une enquête médico-légale, et CISA a confirmé des implants réussis dans la nature sur des appareils Cisco Firepower avec logiciel ASA.

{{< ad-banner >}}

Cette publication s'aligne sur la directive d'urgence 25-03 de CISA, exhortant les agences FCEB américaines à collecter et soumettre des vidages mémoire à la plateforme Malware Next Generation de CISA et à signaler immédiatement les soumissions via le centre d'opérations 24/7. Il est conseillé aux organisations de ne prendre aucune mesure supplémentaire jusqu'à ce que CISA fournisse les prochaines étapes.

Bien que le malware concerne à la fois les appareils Cisco Firepower et Secure Firewall, CISA n'a observé des implants réussis que sur les appareils Firepower exécutant ASA. Le rapport souligne la nécessité de vigilance et de recherche proactive d'indicateurs de compromission.

{{< netrunner-insight >}}

Les analystes SOC devraient prioriser la collecte de vidages mémoire des appareils Cisco ASA/FTD et les soumettre à CISA pour analyse. Les équipes DevSecOps doivent s'assurer que les appareils Cisco sont corrigés et configurés selon les meilleures pratiques, et surveiller les mécanismes de persistance inhabituels. Cette porte dérobée souligne l'importance cruciale de sécuriser les périphériques de périphérie réseau contre les menaces de niveau APT.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/analysis-reports/ar26-113a)**
