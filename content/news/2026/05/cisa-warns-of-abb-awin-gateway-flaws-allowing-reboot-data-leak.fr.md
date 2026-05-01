---
title: "CISA met en garde contre des failles de la passerelle ABB AWIN permettant un redémarrage et une fuite de données"
date: "2026-05-01T08:55:30Z"
original_date: "2026-04-30T12:00:00"
lang: "fr"
translationKey: "cisa-warns-of-abb-awin-gateway-flaws-allowing-reboot-data-leak"
author: "NewsBot (Validated by Federico Sella)"
description: "Les passerelles ABB AWIN présentent des vulnérabilités permettant à des attaquants de redémarrer les appareils ou d'extraire la configuration système. L'avis CISA ICSA-26-120-05 détaille CVE-2025-13777 et les correctifs."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05"
source: "CISA"
severity: "High"
target: "Passerelles ABB AWIN"
cve: "CVE-2025-13777"
cvss: 8.3
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Les passerelles ABB AWIN présentent des vulnérabilités permettant à des attaquants de redémarrer les appareils ou d'extraire la configuration système. L'avis CISA ICSA-26-120-05 détaille CVE-2025-13777 et les correctifs.

{{< cyber-report severity="High" source="CISA" target="Passerelles ABB AWIN" cve="CVE-2025-13777" cvss="8.3" >}}

CISA a publié l'avis ICSA-26-120-05 détaillant de multiples vulnérabilités dans les passerelles ABB AWIN. Les failles, qui incluent un contournement d'authentification par capture-rejeu et l'absence d'authentification pour des fonctions critiques, pourraient permettre à un attaquant non authentifié de redémarrer à distance l'appareil ou d'interroger des données sensibles de configuration système. Les vulnérabilités affectent les versions de firmware AWIN 2.0-0, 2.0-1, 1.2-0 et 1.2-1 fonctionnant sur les matériels GW100 rev.2 et GW120.

{{< ad-banner >}}

Le problème le plus grave, suivi sous le nom CVE-2025-13777, permet une interrogation non authentifiée révélant la configuration système, y compris des détails sensibles. L'avis attribue un score de base CVSS v3 de 8,3, indiquant une sévérité élevée. ABB a publié la version de firmware 2.1-0 pour le GW100 rev.2 afin de corriger ces vulnérabilités. Les organisations utilisant des passerelles concernées sont invitées à appliquer la mise à jour immédiatement.

Les vulnérabilités impactent des actifs critiques du secteur manufacturier déployés dans le monde entier. Compte tenu du potentiel d'exploitation à distance sans authentification, ces failles représentent un risque significatif pour les environnements technologiques opérationnels. CISA recommande aux utilisateurs de consulter l'avis complet et de mettre en œuvre des mesures d'atténuation, notamment la segmentation du réseau et la restriction de l'accès aux appareils concernés.

{{< netrunner-insight >}}

Pour les analystes SOC : surveillez les redémarrages non autorisés ou les requêtes inhabituelles vers les passerelles ABB ; ce sont des indicateurs à faible bruit d'exploitation. Les équipes DevSecOps devraient prioriser le correctif vers le firmware 2.1-0 et appliquer des contrôles d'accès réseau stricts, car les vulnérabilités ne nécessitent aucune authentification et peuvent être exploitées à distance.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05)**
