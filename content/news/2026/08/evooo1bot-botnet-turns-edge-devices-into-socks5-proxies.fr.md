---
title: "Le botnet Evooo1Bot transforme les périphériques en proxys SOCKS5"
date: "2026-08-18T07:31:16Z"
original_date: "2026-08-17T09:29:55"
lang: "fr"
translationKey: "evooo1bot-botnet-turns-edge-devices-into-socks5-proxies"
slug: "evooo1bot-botnet-turns-edge-devices-into-socks5-proxies"
author: "NewsBot (Validated by Federico Sella)"
description: "Le nouveau botnet Linux Evooo1Bot, dérivé de Mirai, exploite des failles connues pour transformer les périphériques en proxys SOCKS5 afin de mener des attaques furtives."
original_url: "https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html"
source: "The Hacker News"
severity: "High"
target: "Périphériques exposés à Internet"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Le nouveau botnet Linux Evooo1Bot, dérivé de Mirai, exploite des failles connues pour transformer les périphériques en proxys SOCKS5 afin de mener des attaques furtives.

{{< cyber-report severity="High" source="The Hacker News" target="Périphériques exposés à Internet" >}}

Des chercheurs en cybersécurité ont identifié une famille de botnets Linux jusqu'alors non documentée, nommée Evooo1Bot, qui tire ses fonctionnalités de base du code source du botnet Mirai divulgué publiquement. Le malware est conçu pour transformer les périphériques exposés à Internet en proxys SOCKS5, permettant aux attaquants de router le trafic malveillant à travers des appareils compromis.

{{< ad-banner >}}

Bien qu'Evooo1Bot réutilise le moteur DDoS de Mirai, il étend le framework d'origine avec des capacités supplémentaires, notamment la possibilité d'exploiter des vulnérabilités connues dans les périphériques. Cela permet au botnet d'étendre sa portée et de maintenir une persistance sur les systèmes compromis.

Cette découverte met en évidence l'évolution continue des botnets basés sur Mirai, qui restent une menace importante en raison de leur capacité à recruter des appareils IoT et périphériques vulnérables dans des réseaux de proxys à grande échelle. Les organisations sont invitées à corriger les vulnérabilités connues et à surveiller le trafic de proxy inhabituel.

{{< netrunner-insight >}}

Pour les analystes SOC, ce botnet souligne l'importance de surveiller le trafic de proxy sortant et de détecter les connexions SOCKS5 inhabituelles. Les équipes DevSecOps devraient prioriser la correction des vulnérabilités connues dans les périphériques et envisager une segmentation du réseau pour limiter l'impact de tels botnets. La réutilisation du code de Mirai signifie que les signatures de détection existantes peuvent nécessiter une mise à jour pour détecter cette nouvelle variante.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html)**
