---
title: "MiniPlasma Windows 0-Day permet une élévation de privilèges SYSTEM sur des systèmes entièrement patchés"
date: "2026-05-18T11:01:35Z"
original_date: "2026-05-18T08:57:34"
lang: "fr"
translationKey: "miniplasma-windows-0-day-enables-system-privilege-escalation-on-fully-patched-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "Le chercheur en sécurité Chaotic Eclipse publie une preuve de concept (PoC) pour MiniPlasma, un zero-day dans le pilote de filtre mini des fichiers cloud Windows (cldflt.sys) accordant les privilèges SYSTEM sur des systèmes entièrement patchés."
original_url: "https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html"
source: "The Hacker News"
severity: "High"
target: "Pilote de filtre mini des fichiers cloud Windows (cldflt.sys)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Le chercheur en sécurité Chaotic Eclipse publie une preuve de concept (PoC) pour MiniPlasma, un zero-day dans le pilote de filtre mini des fichiers cloud Windows (cldflt.sys) accordant les privilèges SYSTEM sur des systèmes entièrement patchés.

{{< cyber-report severity="High" source="The Hacker News" target="Pilote de filtre mini des fichiers cloud Windows (cldflt.sys)" >}}

Chaotic Eclipse, le chercheur en sécurité à l'origine des failles Windows récemment divulguées YellowKey et GreenPlasma, a publié une preuve de concept (PoC) pour une faille zero-day d'élévation de privilèges Windows qui permet aux attaquants d'obtenir les privilèges SYSTEM sur des systèmes Windows entièrement patchés. Surnommée MiniPlasma, la vulnérabilité impacte "cldflt.sys", qui fait référence au pilote de filtre mini des fichiers cloud Windows.

{{< ad-banner >}}

La faille permet à un attaquant disposant d'un accès utilisateur limité d'élever ses privilèges à SYSTEM, permettant potentiellement une compromission complète du système. En tant que zero-day, aucun correctif officiel n'est actuellement disponible, laissant les systèmes entièrement patchés vulnérables à l'exploitation si la PoC est utilisée à mauvais escient.

Les organisations doivent surveiller les comportements inhabituels du pilote cldflt.sys et envisager des mesures de durcissement supplémentaires, telles que la restriction de l'accès à la fonctionnalité Cloud Files ou l'application de mesures d'atténuation temporaires jusqu'à la publication d'un correctif.

{{< netrunner-insight >}}

Les analystes SOC doivent prioriser la surveillance des tentatives d'exploitation ciblant cldflt.sys, car la PoC abaisse la barrière pour les attaquants. Les équipes DevSecOps doivent revoir le durcissement de leurs images Windows et envisager de désactiver le pilote de filtre mini des fichiers cloud si celui-ci n'est pas nécessaire, en attendant un correctif officiel de Microsoft.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)**
