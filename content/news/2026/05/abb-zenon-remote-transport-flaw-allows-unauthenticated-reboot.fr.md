---
title: "Une faille de transport distant dans ABB Zenon permet un redémarrage non authentifié"
date: "2026-05-28T10:50:49Z"
original_date: "2026-05-26T12:00:00"
lang: "fr"
translationKey: "abb-zenon-remote-transport-flaw-allows-unauthenticated-reboot"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA met en garde contre CVE-2025-8754 dans ABB Ability Zenon, permettant des redémarrages système non autorisés via le service de transport distant. Aucune exploitation active signalée."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03"
source: "CISA"
severity: "High"
target: "Systèmes ABB Ability Zenon"
cve: "CVE-2025-8754"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA met en garde contre CVE-2025-8754 dans ABB Ability Zenon, permettant des redémarrages système non autorisés via le service de transport distant. Aucune exploitation active signalée.

{{< cyber-report severity="High" source="CISA" target="Systèmes ABB Ability Zenon" cve="CVE-2025-8754" cvss="7.5" >}}

CISA a publié un avis (ICSA-26-146-03) détaillant une vulnérabilité d'absence d'authentification dans le service de transport distant d'ABB Ability Zenon. La faille, suivie sous le nom CVE-2025-8754 avec un score CVSS de 7,5, permet à un attaquant de déclencher un redémarrage système sans informations d'identification appropriées. Les versions concernées vont de 7.50 à 14.

{{< ad-banner >}}

L'exploitation nécessite un accès réseau préalable, car l'attaquant doit déjà se trouver sur le même réseau que le système Zenon cible. ABB note que dans les configurations par défaut, le service zensyssrv.exe démarre automatiquement, mais les utilisateurs doivent configurer un mot de passe pour utiliser le service de transport distant. Au moment de la rédaction, il n'y a aucune preuve d'exploitation active dans la nature.

L'avis souligne le large déploiement d'ABB Ability Zenon dans les secteurs d'infrastructures critiques, notamment les systèmes chimiques, énergétiques, de santé, ainsi que d'eau et d'eaux usées dans le monde entier. Les organisations utilisant des versions concernées doivent immédiatement appliquer les mesures d'atténuation ou les mises à jour fournies par ABB pour prévenir d'éventuelles attaques par déni de service.

{{< netrunner-insight >}}

Pour les analystes SOC : priorisez la segmentation réseau pour limiter l'exposition des systèmes Zenon, et assurez-vous que les mots de passe du service de transport distant sont configurés et robustes. Les équipes DevSecOps doivent vérifier que le service zensyssrv.exe n'est pas exposé à des réseaux non fiables, et appliquer les correctifs du fournisseur dès qu'ils sont disponibles. Compte tenu du score CVSS de 7,5 et de l'impact sur les infrastructures critiques, traitez cela comme une constatation hautement prioritaire même en l'absence d'exploitation active.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03)**
