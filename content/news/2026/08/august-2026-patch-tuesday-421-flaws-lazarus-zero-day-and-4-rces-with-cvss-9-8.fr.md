---
title: "Patch Tuesday d'août 2026 : 421 failles, zero-day de Lazarus et 4 RCE avec un score CVSS de 9,8"
date: "2026-08-13T08:21:14Z"
original_date: "2026-08-12T08:28:22"
lang: "fr"
translationKey: "august-2026-patch-tuesday-421-flaws-lazarus-zero-day-and-4-rces-with-cvss-9-8"
slug: "august-2026-patch-tuesday-421-flaws-lazarus-zero-day-and-4-rces-with-cvss-9-8"
author: "NewsBot (Validated by Federico Sella)"
description: "Le Patch Tuesday d'août 2026 de Microsoft corrige 421 vulnérabilités, dont un zero-day dans le pilote WinSock exploité par Lazarus et quatre RCE non authentifiés avec un score CVSS de 9,8."
original_url: "https://www.cybersecurity360.it/news/patch-tuesday-agosto-2026-un-driver-windows-il-gruppo-lazarus-e-400-vulnerabilita-sullo-sfondo/"
source: "Cybersecurity360"
severity: "Critical"
target: "Pilote WinSock de Microsoft Windows"
cve: null
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Le Patch Tuesday d'août 2026 de Microsoft corrige 421 vulnérabilités, dont un zero-day dans le pilote WinSock exploité par Lazarus et quatre RCE non authentifiés avec un score CVSS de 9,8.

{{< cyber-report severity="Critical" source="Cybersecurity360" target="Pilote WinSock de Microsoft Windows" cvss="9.8" >}}

Le Patch Tuesday d'août 2026 de Microsoft corrige un total de 421 vulnérabilités, ce qui constitue une mise à jour significative. Parmi celles-ci, une vulnérabilité zero-day dans le pilote Windows WinSock a été activement exploitée par le groupe Lazarus, un acteur de menace nord-coréen bien connu. Ce zero-day est particulièrement préoccupant car il permet aux attaquants d'obtenir des privilèges élevés ou d'exécuter du code arbitraire, compromettant potentiellement les systèmes affectés.

{{< ad-banner >}}

En plus du zero-day, la mise à jour inclut quatre vulnérabilités d'exécution de code à distance (RCE) non authentifiées, toutes évaluées avec un score CVSS de 9,8. Ces failles critiques pourraient être exploitées à distance sans aucune interaction de l'utilisateur, ce qui en fait une priorité absolue pour un correctif immédiat. Le volume considérable de vulnérabilités souligne l'importance d'un processus robuste de gestion des correctifs.

L'article met également en évidence un changement dans les stratégies de gestion des vulnérabilités, notant qu'avec l'adoption de la découverte basée sur l'IA, le tri contextuel devient plus efficace que le tri traditionnel basé sur les scores. Cela suggère que les organisations devraient prioriser les vulnérabilités en fonction de leur environnement spécifique et de leur paysage de menaces, plutôt que de se fier uniquement aux scores CVSS.

{{< netrunner-insight >}}

Pour les analystes SOC, le zero-day de Lazarus dans WinSock doit être traité comme une priorité immédiate, car il est déjà exploité. Appliquez le correctif sur tous les endpoints Windows sans délai. Les équipes DevSecOps devraient tirer parti du contexte basé sur l'IA pour trier les 421 vulnérabilités, en se concentrant sur celles qui sont exposées à Internet ou critiques pour les opérations commerciales, plutôt que de simplement courir après les scores CVSS élevés. N'oubliez pas que les quatre RCE avec un score CVSS de 9,8 ne sont pas authentifiés, ils doivent donc être corrigés avant toute autre mise à jour non critique.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur Cybersecurity360 ›](https://www.cybersecurity360.it/news/patch-tuesday-agosto-2026-un-driver-windows-il-gruppo-lazarus-e-400-vulnerabilita-sullo-sfondo/)**
