---
title: "Une faille dans la pile IEC 61850 d'ABB permet un déni de service sur les systèmes de contrôle industriels"
date: "2026-05-01T09:03:14Z"
original_date: "2026-04-30T12:00:00"
lang: "fr"
translationKey: "abb-iec-61850-stack-flaw-enables-dos-on-industrial-control-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA met en garde contre une vulnérabilité signalée de manière privée dans l'implémentation IEC 61850 MMS d'ABB affectant les produits System 800xA et Symphony Plus, entraînant des défauts de dispositif et un déni de service."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01"
source: "CISA"
severity: "High"
target: "ABB System 800xA, Symphony Plus IEC 61850"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA met en garde contre une vulnérabilité signalée de manière privée dans l'implémentation IEC 61850 MMS d'ABB affectant les produits System 800xA et Symphony Plus, entraînant des défauts de dispositif et un déni de service.

{{< cyber-report severity="High" source="CISA" target="ABB System 800xA, Symphony Plus IEC 61850" >}}

CISA a publié un avis (ICSA-26-120-01) concernant une vulnérabilité dans l'implémentation par ABB de la pile de communication IEC 61850 pour les applications client MMS. La faille affecte plusieurs produits des gammes System 800xA et Symphony Plus, notamment AC800M CI868, Symphony Plus SD Series CI850, PM 877 et S+ Operations. L'exploitation nécessite un accès préalable au réseau IEC 61850 du site.

{{< ad-banner >}}

Une exploitation réussie provoque un défaut de dispositif sur les modules PM 877, CI850 et CI868, nécessitant un redémarrage manuel. Pour les nœuds S+ Operations, l'attaque fait planter le pilote de communication IEC 61850, entraînant une condition de déni de service si elle est répétée. Cependant, la disponibilité et la fonctionnalité globales du nœud restent inchangées, et la communication du protocole GOOSE n'est pas impactée. Le System 800xA IEC61850 Connect n'est pas non plus vulnérable.

Les versions de firmware affectées couvrent plusieurs branches, notamment S+ Operations jusqu'à 6.2.0006.0 et diverses versions de PM 877. Aucun identifiant CVE ni score CVSS n'a été fourni dans l'avis. Les organisations utilisant ces produits doivent examiner l'avis et appliquer des mesures d'atténuation, telles que la segmentation du réseau et les contrôles d'accès, pour limiter l'exposition au réseau IEC 61850.

{{< netrunner-insight >}}

Cette vulnérabilité souligne l'importance de la segmentation du réseau dans les environnements OT. Étant donné que l'exploitation nécessite un accès au réseau IEC 61850, isoler ce réseau du réseau informatique de l'entreprise et d'Internet est essentiel. Les analystes SOC doivent surveiller le trafic IEC 61850 anormal, tandis que les ingénieurs DevSecOps doivent prioriser le patching et envisager la mise en place d'une détection d'intrusion pour les anomalies du protocole MMS.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01)**
