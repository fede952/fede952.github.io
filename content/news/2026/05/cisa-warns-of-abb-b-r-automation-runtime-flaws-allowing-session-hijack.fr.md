---
title: "CISA met en garde contre des vulnérabilités dans ABB B&R Automation Runtime permettant le détournement de session"
date: "2026-05-22T10:20:32Z"
original_date: "2026-05-21T12:00:00"
lang: "fr"
translationKey: "cisa-warns-of-abb-b-r-automation-runtime-flaws-allowing-session-hijack"
author: "NewsBot (Validated by Federico Sella)"
description: "De multiples vulnérabilités dans ABB B&R Automation Runtime avant la version 6.4 pourraient permettre à des attaquants de détourner des sessions ou d'exécuter du code. L'avis CISA ICSA-26-141-04 détaille les correctifs."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04"
source: "CISA"
severity: "Medium"
target: "ABB B&R Automation Runtime"
cve: "CVE-2025-3449"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

De multiples vulnérabilités dans ABB B&R Automation Runtime avant la version 6.4 pourraient permettre à des attaquants de détourner des sessions ou d'exécuter du code. L'avis CISA ICSA-26-141-04 détaille les correctifs.

{{< cyber-report severity="Medium" source="CISA" target="ABB B&R Automation Runtime" cve="CVE-2025-3449" cvss="6.1" >}}

CISA a publié l'avis ICSA-26-141-04 détaillant de multiples vulnérabilités dans ABB B&R Automation Runtime, une plateforme logicielle utilisée dans l'automatisation industrielle. Les failles, identifiées par l'analyse de sécurité interne de B&R, affectent les versions antérieures à 6.4 et incluent CVE-2025-3449 (identifiants de session prévisibles), CVE-2025-3448 (cross-site scripting) et CVE-2025-11498 (neutralisation incorrecte des éléments de formule dans les fichiers CSV). Un attaquant non authentifié pourrait les exploiter pour détourner des sessions distantes ou exécuter du code dans le contexte du navigateur d'un utilisateur.

{{< ad-banner >}}

La vulnérabilité la plus grave, CVE-2025-3449, réside dans le composant System Diagnostic Manager (SDM) et obtient un score CVSS v3 de 6.1. Elle permet à un attaquant non authentifié basé sur le réseau de prendre le contrôle de sessions déjà établies en raison de la génération de nombres ou d'identifiants prévisibles. Le SDM est désactivé par défaut dans Automation Runtime 6, ce qui réduit l'exposition, mais les organisations doivent vérifier qu'il reste désactivé sauf si nécessaire.

ABB a publié la version 6.4 d'Automation Runtime pour corriger ces problèmes. Compte tenu du déploiement du produit dans le secteur de l'énergie à l'échelle mondiale, CISA exhorte les opérateurs à appliquer la mise à jour rapidement. L'avis note qu'une exploitation réussie pourrait entraîner une exécution de code à distance ou un détournement de session, posant un risque significatif pour les environnements de contrôle industriel.

{{< netrunner-insight >}}

Pour les analystes SOC : priorisez le correctif des instances Automation Runtime, en particulier celles avec SDM activé. La faille d'identifiant de session prévisible (CVE-2025-3449) est trivialement exploitable sur le réseau. Les équipes DevSecOps doivent s'assurer que SDM reste désactivé en production et vérifier qu'aucune instance exposée n'est accessible depuis des réseaux non fiables. Surveillez toute activité de session anormale comme signal de détection.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04)**
