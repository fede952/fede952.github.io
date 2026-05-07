---
title: "Le botnet xlabs_v1 dérivé de Mirai détourne des appareils IoT via ADB pour des DDoS"
date: "2026-05-07T09:27:29Z"
original_date: "2026-05-06T20:21:00"
lang: "fr"
translationKey: "mirai-derived-xlabs-v1-botnet-hijacks-iot-devices-via-adb-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "Des chercheurs découvrent xlabs_v1, un nouveau botnet basé sur Mirai exploitant les ports Android Debug Bridge exposés pour recruter des appareils IoT dans un réseau DDoS."
original_url: "https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html"
source: "The Hacker News"
severity: "High"
target: "Appareils IoT avec ADB exposé"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Des chercheurs découvrent xlabs_v1, un nouveau botnet basé sur Mirai exploitant les ports Android Debug Bridge exposés pour recruter des appareils IoT dans un réseau DDoS.

{{< cyber-report severity="High" source="The Hacker News" target="Appareils IoT avec ADB exposé" >}}

Des chercheurs en cybersécurité ont identifié un nouveau botnet dérivé de Mirai, s'identifiant comme xlabs_v1, qui cible les appareils exposés à Internet exécutant Android Debug Bridge (ADB). Le botnet vise à enrôler les appareils compromis dans un réseau capable de lancer des attaques par déni de service distribué (DDoS).

{{< ad-banner >}}

La découverte a été faite par Hunt.io après avoir identifié un répertoire exposé sur un serveur hébergé aux Pays-Bas. Le logiciel malveillant exploite ADB, un outil en ligne de commande utilisé pour le débogage des appareils Android, qui est souvent laissé exposé sur les appareils IoT, permettant à des attaquants distants d'obtenir un accès non autorisé.

Cette campagne met en lumière la menace persistante des variantes de Mirai ciblant les appareils IoT mal sécurisés. Il est conseillé aux organisations de désactiver ADB sur les appareils de production et de restreindre l'accès réseau pour éviter un tel détournement.

{{< netrunner-insight >}}

Pour les analystes SOC, surveillez les connexions ADB inattendues provenant d'IP externes. Les équipes DevSecOps doivent s'assurer qu'ADB est désactivé dans les builds de production et que les appareils IoT sont segmentés des réseaux critiques pour limiter la portée de ce botnet.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html)**
