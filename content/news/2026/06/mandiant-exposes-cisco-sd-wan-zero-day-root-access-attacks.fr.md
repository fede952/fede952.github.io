---
title: "Mandiant révèle des attaques zero-day sur Cisco SD-WAN avec accès root"
date: "2026-06-25T10:15:15Z"
original_date: "2026-06-24T21:29:10"
lang: "fr"
translationKey: "mandiant-exposes-cisco-sd-wan-zero-day-root-access-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "De nouveaux détails montrent comment des pirates ont exploité CVE-2026-20245 lors d'attaques zero-day pour créer des comptes root illégitimes sur des appareils Cisco Catalyst SD-WAN."
original_url: "https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/"
source: "BleepingComputer"
severity: "High"
target: "Appareils Cisco Catalyst SD-WAN"
cve: "CVE-2026-20245"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

De nouveaux détails montrent comment des pirates ont exploité CVE-2026-20245 lors d'attaques zero-day pour créer des comptes root illégitimes sur des appareils Cisco Catalyst SD-WAN.

{{< cyber-report severity="High" source="BleepingComputer" target="Appareils Cisco Catalyst SD-WAN" cve="CVE-2026-20245" >}}

Mandiant a divulgué de nouveaux détails techniques sur la manière dont des acteurs malveillants ont exploité une vulnérabilité zero-day dans le logiciel Cisco Catalyst SD-WAN, suivie sous le nom CVE-2026-20245, pour obtenir un accès root sur les appareils ciblés. Les attaques impliquaient la création de comptes root illégitimes, permettant un accès non autorisé persistant.

{{< ad-banner >}}

La vulnérabilité, corrigée par Cisco dans un récent avis, a été utilisée dans des attaques ciblées limitées. L'analyse de Mandiant révèle la chaîne d'exploitation spécifique, soulignant l'importance d'appliquer rapidement les mises à jour de sécurité.

Les organisations utilisant des solutions Cisco SD-WAN sont invitées à auditer leurs systèmes pour détecter des signes de compromission, tels que des comptes non autorisés ou une activité root inhabituelle. Cet incident souligne la nécessité cruciale d'une gestion robuste des correctifs et d'une surveillance de l'infrastructure réseau.

{{< netrunner-insight >}}

Pour les analystes SOC, priorisez la surveillance des événements de création de comptes non autorisés et d'élévation de privilèges sur les appliances Cisco SD-WAN. Les équipes DevSecOps doivent assurer un déploiement rapide des correctifs de sécurité de Cisco et envisager de segmenter les interfaces de gestion SD-WAN pour réduire la surface d'attaque.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/)**
