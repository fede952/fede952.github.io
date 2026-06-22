---
title: "Le botnet AryStinger détourne plus de 4 000 routeurs D-Link pour du trafic proxy"
date: "2026-06-22T12:48:45Z"
original_date: "2026-06-21T14:14:22"
lang: "fr"
translationKey: "arystinger-botnet-hijacks-4000-d-link-routers-for-proxy-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Un nouveau botnet nommé AryStinger a compromis plus de 4 000 routeurs D-Link obsolètes, les transformant en proxies pour du trafic malveillant. Aucune donnée CVE ou CVSS n'est disponible."
original_url: "https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/"
source: "BleepingComputer"
severity: "Medium"
target: "Routeurs D-Link obsolètes"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un nouveau botnet nommé AryStinger a compromis plus de 4 000 routeurs D-Link obsolètes, les transformant en proxies pour du trafic malveillant. Aucune donnée CVE ou CVSS n'est disponible.

{{< cyber-report severity="Medium" source="BleepingComputer" target="Routeurs D-Link obsolètes" >}}

Un botnet malveillant jusqu'alors non documenté, nommé AryStinger, a compromis plus de 4 000 routeurs D-Link obsolètes dans le monde, selon un rapport de BleepingComputer. Le botnet transforme ces appareils en proxies pour du trafic malveillant, permettant aux attaquants d'anonymiser leurs activités et potentiellement de lancer d'autres attaques.

{{< ad-banner >}}

Les routeurs compromis exécuteraient un firmware obsolète présentant des vulnérabilités connues, bien qu'aucun identifiant CVE spécifique n'ait été divulgué dans le rapport. L'infrastructure du botnet et ses méthodes de propagation sont encore en cours d'analyse, mais l'ampleur de l'infection souligne les risques posés par les appareils IoT non patchés.

Il est conseillé aux organisations d'inventorier leurs appareils réseau, de s'assurer que le firmware est à jour et de surveiller les schémas de trafic inhabituels pouvant indiquer une utilisation de proxy. L'absence d'indicateurs techniques détaillés dans le rapport initial suggère que des investigations supplémentaires sont nécessaires pour développer des signatures de détection.

{{< netrunner-insight >}}

Pour les analystes SOC, c'est un rappel de surveiller les connexions sortantes inattendues provenant des appareils réseau, en particulier les routeurs plus anciens. Les équipes DevSecOps devraient appliquer des politiques de mise à jour du firmware et envisager de segmenter les appareils IoT des réseaux critiques. Sans IoC spécifiques, l'analyse du trafic de base et l'empreinte des appareils sont essentielles pour repérer une telle activité de botnet.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/)**
