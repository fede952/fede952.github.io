---
title: "CISA met en garde contre une faille dans l'ouvre-porte ABB permettant un contournement de l'accès physique"
date: "2026-05-30T09:11:24Z"
original_date: "2026-05-28T12:00:00"
lang: "fr"
translationKey: "cisa-warns-of-abb-door-opener-flaw-allowing-physical-access-bypass"
author: "NewsBot (Validated by Federico Sella)"
description: "L'avis CISA ICSA-26-148-04 détaille une vulnérabilité de contournement d'authentification (CVE-2025-7705) dans l'actionneur d'ouvre-porte filaire ABB Busch-Welcome 2, permettant un accès non autorisé aux bâtiments."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04"
source: "CISA"
severity: "Medium"
target: "Actionneur d'ouvre-porte filaire ABB Busch-Welcome 2"
cve: "CVE-2025-7705"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

L'avis CISA ICSA-26-148-04 détaille une vulnérabilité de contournement d'authentification (CVE-2025-7705) dans l'actionneur d'ouvre-porte filaire ABB Busch-Welcome 2, permettant un accès non autorisé aux bâtiments.

{{< cyber-report severity="Medium" source="CISA" target="Actionneur d'ouvre-porte filaire ABB Busch-Welcome 2" cve="CVE-2025-7705" cvss="6.8" >}}

CISA a publié l'avis ICSA-26-148-04 concernant une vulnérabilité de contournement d'authentification dans l'actionneur d'ouvre-porte filaire ABB Busch-Welcome 2, identifiée sous le code CVE-2025-7705. La faille provient d'un mode de compatibilité activé par défaut, qui permet à un attaquant d'obtenir un accès physique non autorisé aux bâtiments où le produit concerné est installé. La vulnérabilité affecte toutes les versions de l'actionneur d'interrupteur 4 DU et de l'actionneur d'interrupteur, porte/lumière 4 DU.

{{< ad-banner >}}

Le score de base CVSS v3 pour cette vulnérabilité est de 6,8, indiquant une sévérité moyenne. ABB a fourni des mesures de correction qui consistent à basculer le commutateur de mode sur le produit et à effectuer une réinitialisation électrique pour recalibrer le système. Le produit est déployé dans le monde entier, principalement dans des installations commerciales, et le fabricant a son siège en Suisse.

Les organisations utilisant les systèmes ABB Busch-Welcome concernés doivent immédiatement appliquer les mesures d'atténuation recommandées. Compte tenu des implications pour la sécurité physique, cette vulnérabilité présente un risque significatif pour le contrôle d'accès aux bâtiments. Les équipes de sécurité doivent vérifier que les étapes de recalibrage sont exécutées correctement et surveiller tout signe d'exploitation.

{{< netrunner-insight >}}

Cette vulnérabilité est un rappel frappant que les appareils IoT et d'automatisation des bâtiments sont souvent livrés avec des paramètres par défaut non sécurisés. Les analystes SOC doivent prioriser la découverte d'actifs pour les systèmes ABB Busch-Welcome et s'assurer que le recalibrage manuel est appliqué. Les équipes DevSecOps doivent plaider en faveur de principes de conception sécurisée, en particulier pour les appareils contrôlant l'accès physique.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04)**
