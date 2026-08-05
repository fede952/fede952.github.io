---
title: "Attaque de la chaîne d'approvisionnement de QuickFox : un installateur piégé distribue la porte dérobée FDMTP"
date: "2026-08-05T09:34:12Z"
original_date: "2026-08-05T05:47:19"
lang: "fr"
translationKey: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
slug: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
author: "NewsBot (Validated by Federico Sella)"
description: "Une attaque de longue durée sur la chaîne d'approvisionnement de QuickFox VPN piège l'installateur pour déployer la porte dérobée FDMTP, ciblant les utilisateurs chinois à l'étranger depuis août 2025."
original_url: "https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html"
source: "The Hacker News"
severity: "High"
target: "Utilisateurs de QuickFox VPN"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Une attaque de longue durée sur la chaîne d'approvisionnement de QuickFox VPN piège l'installateur pour déployer la porte dérobée FDMTP, ciblant les utilisateurs chinois à l'étranger depuis août 2025.

{{< cyber-report severity="High" source="The Hacker News" target="Utilisateurs de QuickFox VPN" >}}

Fortinet FortiGuard Labs a révélé une attaque de longue durée sur la chaîne d'approvisionnement ciblant QuickFox, un outil VPN et d'accélération réseau populaire auprès des utilisateurs chinois à l'étranger. L'attaque, active depuis au moins août 2025, implique une version piégée de l'installateur Windows de l'application qui distribue une porte dérobée nommée FDMTP.

{{< ad-banner >}}

L'installateur piégé est distribué via des canaux officiels ou de confiance, compromettant l'intégrité de la chaîne d'approvisionnement logicielle. Une fois exécuté, FDMTP fournit aux attaquants un accès et un contrôle à distance sur le système de la victime, pouvant conduire à un vol de données, une surveillance ou un déploiement de logiciels malveillants supplémentaires.

Cet incident met en évidence le risque croissant des attaques de la chaîne d'approvisionnement sur des outils de niche mais de confiance, en particulier ceux qui servent des communautés spécifiques. Les organisations et les individus utilisant QuickFox devraient vérifier l'intégrité de leurs installations et surveiller les indicateurs de compromission associés à FDMTP.

{{< netrunner-insight >}}

Cette attaque souligne la nécessité d'une vérification robuste de l'intégrité des logiciels, même pour des outils provenant de fournisseurs apparemment réputés. Les analystes SOC devraient rechercher les indicateurs de FDMTP et surveiller les connexions réseau inhabituelles provenant des clients VPN. Les équipes DevSecOps doivent imposer la signature de code et la vérification des empreintes numériques dans leurs pipelines de déploiement logiciel pour atténuer ces risques de chaîne d'approvisionnement.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html)**
