---
title: "TeamPCP lié à des attaques Redis depuis 2020, puis à une campagne de supply chain"
date: "2026-08-07T08:10:37Z"
original_date: "2026-08-07T06:50:05"
lang: "fr"
translationKey: "teampcp-linked-to-redis-attacks-since-2020-later-supply-chain-campaign"
slug: "teampcp-linked-to-redis-attacks-since-2020-later-supply-chain-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "Une nouvelle analyse relie TeamPCP à des attaques Redis remontant à 2020, révélant des années de compromission d'infrastructures avant de se concentrer sur la supply chain."
original_url: "https://thehackernews.com/2026/08/teampcp-linked-to-redis-attacks-dating.html"
source: "The Hacker News"
severity: "Medium"
target: "Infrastructures exposées à Internet"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Une nouvelle analyse relie TeamPCP à des attaques Redis remontant à 2020, révélant des années de compromission d'infrastructures avant de se concentrer sur la supply chain.

{{< cyber-report severity="Medium" source="The Hacker News" target="Infrastructures exposées à Internet" >}}

Une analyse récente a révélé que l'acteur de la menace connu sous le nom de TeamPCP est actif dans le paysage de la cybercriminalité depuis au moins 2020, indiquant une longue histoire de compromission d'infrastructures exposées à Internet. Les activités du groupe ont désormais été liées à une campagne ultérieure de supply chain logicielle, suggérant une évolution stratégique de ses opérations.

{{< ad-banner >}}

Le lien entre les attaques Redis antérieures et la campagne de supply chain est étayé par des domaines se chevauchant, des chemins de déploiement de logiciels malveillants, des techniques de staging et des infrastructures backend. Ces points communs fournissent des preuves solides que le même acteur est responsable des deux ensembles d'activités, soulignant l'importance du renseignement sur les menaces historiques pour attribuer et comprendre les attaques modernes.

Pour les défenseurs, cette chronologie souligne la nécessité de surveiller les indicateurs de compromission qui peuvent s'étendre sur plusieurs années et de considérer la possibilité que les acteurs de la menace passent d'attaques opportunistes à des opérations de supply chain plus ciblées. Les conclusions soulignent également la valeur du partage de renseignements sur les menaces entre organisations pour identifier ces schémas à long terme.

{{< netrunner-insight >}}

Pour les analystes SOC, ce rapport renforce l'importance de corréler les indicateurs historiques avec les menaces actuelles—l'utilisation par TeamPCP d'infrastructures qui se chevauchent signifie que les anciens IoC peuvent toujours être pertinents. Les équipes DevSecOps devraient considérer les services exposés à Internet comme Redis comme des cibles de grande valeur et garantir une gestion robuste des correctifs et une surveillance, car les attaquants peuvent rôder pendant des années avant de frapper. Les défenseurs de la supply chain devraient également vérifier les composants tiers pour détecter des liens avec des infrastructures malveillantes connues, car ce groupe démontre une progression claire des attaques directes vers des compromissions de supply chain plus insidieuses.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/08/teampcp-linked-to-redis-attacks-dating.html)**
