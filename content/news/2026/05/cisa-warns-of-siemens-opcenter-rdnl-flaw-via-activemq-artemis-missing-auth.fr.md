---
title: "CISA met en garde contre une faille dans Siemens Opcenter RDnL via ActiveMQ Artemis sans authentification"
date: "2026-05-17T08:59:55Z"
original_date: "2026-05-14T12:00:00"
lang: "fr"
translationKey: "cisa-warns-of-siemens-opcenter-rdnl-flaw-via-activemq-artemis-missing-auth"
author: "NewsBot (Validated by Federico Sella)"
description: "Siemens Opcenter RDnL est affecté par CVE-2026-27446, une vulnérabilité d'absence d'authentification dans ActiveMQ Artemis qui permet à des attaquants adjacents non authentifiés d'injecter ou d'exfiltrer des messages."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09"
source: "CISA"
severity: "High"
target: "Siemens Opcenter RDnL"
cve: "CVE-2026-27446"
cvss: 7.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Siemens Opcenter RDnL est affecté par CVE-2026-27446, une vulnérabilité d'absence d'authentification dans ActiveMQ Artemis qui permet à des attaquants adjacents non authentifiés d'injecter ou d'exfiltrer des messages.

{{< cyber-report severity="High" source="CISA" target="Siemens Opcenter RDnL" cve="CVE-2026-27446" cvss="7.1" >}}

CISA a publié un avis (ICSA-26-134-09) détaillant une vulnérabilité d'absence d'authentification pour une fonction critique dans Apache ActiveMQ Artemis, affectant Siemens Opcenter RDnL. La faille, suivie sous le nom CVE-2026-27446 avec un score CVSS v3 de 7.1, permet à un attaquant non authentifié situé sur le réseau adjacent de forcer un courtier cible à établir une connexion de fédération Core sortante vers un courtier malveillant. Cela peut conduire à l'injection de messages dans n'importe quelle file d'attente ou à l'exfiltration de messages depuis n'importe quelle file via le courtier malveillant.

{{< ad-banner >}}

La vulnérabilité impacte toutes les versions de Siemens Opcenter RDnL. Bien que l'impact sur l'intégrité soit considéré comme faible en raison de l'absence de fonctionnalité d'actualisation automatique et de l'absence d'informations confidentielles dans les messages, l'impact sur la disponibilité et le potentiel de manipulation des messages restent significatifs. ActiveMQ Artemis a publié un correctif, et Siemens recommande de mettre à jour immédiatement vers la dernière version.

Compte tenu du déploiement mondial dans le secteur de la fabrication critique, les organisations utilisant Opcenter RDnL devraient prioriser le correctif. Le vecteur d'attaque par réseau adjacent réduit l'exposition immédiate mais présente toujours un risque dans les environnements segmentés. Les équipes bleues doivent surveiller les connexions de fédération Core inhabituelles et l'activité de courtiers malveillants.

{{< netrunner-insight >}}

Pour les analystes SOC, surveillez les connexions de fédération Core sortantes inattendues provenant des courtiers ActiveMQ Artemis, car c'est le principal indicateur d'exploitation. Les équipes DevSecOps doivent immédiatement mettre à jour vers la dernière version d'ActiveMQ Artemis et restreindre l'accès au protocole Core aux seuls réseaux de confiance. Cette faille souligne le risque lié à l'absence d'authentification dans les composants middleware, même lorsque l'impact immédiat semble faible.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09)**
