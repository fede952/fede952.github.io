---
title: "Le botnet RustDuck détourne des routeurs et caméras pour des DDoS"
date: "2026-07-01T10:41:08Z"
original_date: "2026-06-30T17:45:25"
lang: "fr"
translationKey: "rustduck-botnet-hijacks-routers-cameras-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "Une nouvelle famille de malwares en deux étapes appelée RustDuck détourne des routeurs domestiques, des caméras IP, des boîtiers Android et des serveurs mal sécurisés pour constituer un réseau DDoS, suivie depuis février 2026."
original_url: "https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html"
source: "The Hacker News"
severity: "High"
target: "Routeurs, caméras IP, boîtiers Android, serveurs"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Une nouvelle famille de malwares en deux étapes appelée RustDuck détourne des routeurs domestiques, des caméras IP, des boîtiers Android et des serveurs mal sécurisés pour constituer un réseau DDoS, suivie depuis février 2026.

{{< cyber-report severity="High" source="The Hacker News" target="Routeurs, caméras IP, boîtiers Android, serveurs" >}}

Des chercheurs du XLab de QiAnXin suivent une nouvelle famille de malwares en deux étapes appelée RustDuck depuis février 2026. Le botnet détourne des routeurs domestiques, des caméras IP, des boîtiers Android et des serveurs mal sécurisés, les assemblant en un réseau conçu pour mettre hors ligne des sites web et des services en ligne via des attaques DDoS.

{{< ad-banner >}}

Le malware est remarquable car il a été reconstruit en Rust, un langage à mémoire sécurisée qui complique l'analyse et le rétro-ingénierie. Bien que la taille actuelle du botnet ne soit pas massive, son évolution rapide et son adaptabilité constituent une menace croissante pour l'infrastructure Internet.

RustDuck représente un changement dans le développement des botnets, exploitant les performances et les fonctionnalités de sécurité de Rust pour créer des malwares plus résilients et plus difficiles à détecter. L'objectif final est de construire un réseau DDoS robuste capable de faire tomber des cibles majeures.

{{< netrunner-insight >}}

Pour les analystes SOC : surveillez le trafic sortant inhabituel provenant des appareils IoT et des routeurs, car l'infection en deux étapes de RustDuck peut échapper aux signatures traditionnelles. Les équipes DevSecOps doivent imposer une segmentation réseau stricte et désactiver les services inutiles sur les appareils exposés pour réduire la surface d'attaque.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html)**
