---
title: "Le FBI saisit le service proxy NetNut et l'infrastructure du botnet Popa"
date: "2026-07-04T09:20:04Z"
original_date: "2026-07-02T19:27:33"
lang: "fr"
translationKey: "fbi-seizes-netnut-proxy-service-and-popa-botnet-infrastructure"
author: "NewsBot (Validated by Federico Sella)"
description: "Le FBI a saisi des domaines liés à NetNut, un service proxy résidentiel associé au botnet Popa de 2 millions d'appareils compromis, suite à un rapport d'enquête."
original_url: "https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/"
source: "Krebs on Security"
severity: "High"
target: "Service proxy résidentiel NetNut et botnet Popa"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Le FBI a saisi des domaines liés à NetNut, un service proxy résidentiel associé au botnet Popa de 2 millions d'appareils compromis, suite à un rapport d'enquête.

{{< cyber-report severity="High" source="Krebs on Security" target="Service proxy résidentiel NetNut et botnet Popa" >}}

Le FBI, en coordination avec des partenaires industriels, a saisi des centaines de domaines associés à NetNut, un service proxy résidentiel exploité par la société israélienne cotée en bourse Alarum Technologies (NASDAQ : ALAR). Cette action fait suite à un rapport de KrebsOnSecurity liant NetNut au botnet Popa, un réseau d'au moins deux millions d'appareils compromis sans le consentement des utilisateurs.

{{< ad-banner >}}

Le botnet Popa exploite les appareils infectés pour acheminer le trafic via l'infrastructure proxy de NetNut, permettant des activités malveillantes telles que le credential stuffing, la fraude publicitaire et le vol de comptes. La saisie perturbe à la fois le service proxy et les capacités de commande et de contrôle du botnet.

Cette opération met en lumière la tendance croissante des forces de l'ordre à cibler les services proxy qui facilitent la cybercriminalité. Les organisations devraient examiner leur trafic réseau pour détecter des connexions vers les domaines saisis et surveiller toute activité résiduelle du botnet.

{{< netrunner-insight >}}

Pour les analystes SOC, cette démantèlement souligne l'importance de surveiller les plages IP de proxy résidentiels dans les flux de renseignements sur les menaces. Les équipes DevSecOps doivent auditer toute intégration avec des services proxy tiers et s'assurer que des mécanismes robustes de détection de botnets sont en place, car des vestiges de Popa pourraient persister dans une infrastructure alternative.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur Krebs on Security ›](https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/)**
