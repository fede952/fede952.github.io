---
title: "Fausse mise à jour de navigateur sur le Wi-Fi d'un hôtel distribue le RAT CornFlake"
date: "2026-08-01T09:04:02Z"
original_date: "2026-08-01T06:29:05"
lang: "fr"
translationKey: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
slug: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft met en garde contre l'opération CaptiveCrunch qui utilise le Wi-Fi d'hôtels piratés pour pousser de fausses mises à jour et distribuer le logiciel espion CornFlake."
original_url: "https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html"
source: "The Hacker News"
severity: "High"
target: "Utilisateurs du Wi-Fi d'hôtel"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft met en garde contre l'opération CaptiveCrunch qui utilise le Wi-Fi d'hôtels piratés pour pousser de fausses mises à jour et distribuer le logiciel espion CornFlake.

{{< cyber-report severity="High" source="The Hacker News" target="Utilisateurs du Wi-Fi d'hôtel" >}}

Microsoft a révélé une nouvelle campagne suivie sous le nom de CaptiveCrunch, qui exploite des réseaux Wi-Fi d'hôtels piratés pour servir de fausses mises à jour de navigateur. Ces mises à jour sont en réalité un cheval de Troie d'accès à distance (RAT) nommé CornFlake, capable de capturer des images de webcam, de l'audio de microphone et des frappes clavier, transformant efficacement les appareils infectés en outils de surveillance.

{{< ad-banner >}}

L'opération est attribuée à Storm-2945, que Microsoft évalue comme un sous-cluster opérationnel du groupe de menace bien connu Midnight Blizzard. Cela suggère un niveau élevé de sophistication et de ressources, car la chaîne d'attaque implique de compromettre l'infrastructure réseau des hôtels pour intercepter et rediriger le trafic des utilisateurs vers des pages de mise à jour malveillantes.

Bien que le rapport ne spécifie pas de CVE ou de score CVSS particulier, le vecteur d'attaque est notable pour son utilisation d'un environnement de confiance (Wi-Fi d'hôtel) pour distribuer des logiciels malveillants. Les voyageurs et les professionnels en déplacement sont particulièrement à risque, car ils dépendent souvent du Wi-Fi public et peuvent être plus susceptibles d'accepter les invites de mise à jour du navigateur sans les examiner.

{{< netrunner-insight >}}

Cette campagne souligne l'importance de traiter toute invite de mise à jour de navigateur sur des réseaux non fiables avec suspicion. Les analystes SOC doivent surveiller les connexions sortantes inhabituelles depuis les points de terminaison qui se sont récemment connectés au Wi-Fi d'hôtel ou public, et envisager de bloquer ou de signaler les domaines liés aux mises à jour qui ne sont pas sur la liste blanche de l'organisation. Pour DevSecOps, appliquer des politiques de mise à jour strictes et utiliser des VPN d'entreprise pour les travailleurs à distance peut atténuer le risque de telles attaques de type watering-hole.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html)**
