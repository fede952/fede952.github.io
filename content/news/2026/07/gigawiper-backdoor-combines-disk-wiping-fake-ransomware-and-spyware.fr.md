---
title: "Backdoor GigaWiper combine effacement de disque, faux ransomware et logiciel espion"
date: "2026-07-10T10:21:21Z"
original_date: "2026-07-09T18:08:07"
lang: "fr"
translationKey: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
slug: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft découvre GigaWiper, une backdoor modulaire pour Windows qui regroupe trois outils destructeurs : effaceur de disque, faux ransomware et logiciel espion, représentant une menace sévère pour les endpoints."
original_url: "https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html"
source: "The Hacker News"
severity: "High"
target: "Endpoints Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft découvre GigaWiper, une backdoor modulaire pour Windows qui regroupe trois outils destructeurs : effaceur de disque, faux ransomware et logiciel espion, représentant une menace sévère pour les endpoints.

{{< cyber-report severity="High" source="The Hacker News" target="Endpoints Windows" >}}

Microsoft a identifié une nouvelle backdoor destructive pour Windows nommée GigaWiper, qui intègre trois programmes malveillants plus anciens dans un cadre modulaire unique. La backdoor offre aux opérateurs un menu de commandes parmi lesquelles choisir, chacune conçue pour infliger un type de dommage différent : effacement complet du disque, écrasement du lecteur système Windows, ou exécution d'un faux ransomware qui chiffre les fichiers avec une clé qui n'est jamais sauvegardée.

{{< ad-banner >}}

La conception modulaire de GigaWiper permet aux attaquants d'adapter leurs actions destructrices en fonction de l'environnement cible. L'inclusion de capacités d'effacement de disque et de faux ransomware suggère que l'objectif principal est de causer un maximum de perturbations et de pertes de données, plutôt qu'un gain financier. Cette combinaison de techniques fait de GigaWiper un outil polyvalent et dangereux pour les opérations cybernétiques destructrices.

Bien que le vecteur de distribution spécifique reste non divulgué, la capacité de la backdoor à effacer des disques entiers et à simuler des attaques de ransomware indique un haut niveau de sophistication. Les organisations devraient prioriser les solutions de détection et de réponse des endpoints (EDR) et garantir des stratégies de sauvegarde robustes pour atténuer l'impact de telles menaces.

{{< netrunner-insight >}}

Pour les analystes SOC, GigaWiper souligne le besoin de règles de détection comportementale qui signalent les opérations massives sur les fichiers et les écritures au niveau du disque. Les équipes DevSecOps doivent valider l'intégrité des sauvegardes et tester régulièrement les procédures de récupération, car un faux ransomware peut contourner les approches de déchiffrement traditionnelles. Traitez tout incident de ransomware non vérifié comme une potentielle attaque par wiper jusqu'à preuve du contraire.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html)**
