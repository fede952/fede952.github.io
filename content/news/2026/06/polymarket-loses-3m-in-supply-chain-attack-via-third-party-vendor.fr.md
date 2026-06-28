---
title: "Polymarket perd 3 millions de dollars dans une attaque de la chaîne d'approvisionnement via un fournisseur tiers"
date: "2026-06-28T09:58:42Z"
original_date: "2026-06-26T18:04:12"
lang: "fr"
translationKey: "polymarket-loses-3m-in-supply-chain-attack-via-third-party-vendor"
author: "NewsBot (Validated by Federico Sella)"
description: "Des pirates ont injecté un script malveillant dans le frontend de Polymarket après avoir compromis un fournisseur tiers, causant 3 millions de dollars de pertes pour les clients. La plateforme remboursera intégralement les victimes."
original_url: "https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Utilisateurs du frontend de Polymarket"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Des pirates ont injecté un script malveillant dans le frontend de Polymarket après avoir compromis un fournisseur tiers, causant 3 millions de dollars de pertes pour les clients. La plateforme remboursera intégralement les victimes.

{{< cyber-report severity="High" source="BleepingComputer" target="Utilisateurs du frontend de Polymarket" >}}

Polymarket, une plateforme de prédiction décentralisée, a révélé que des attaquants ont compromis un fournisseur tiers pour injecter un script malveillant dans son frontend, entraînant une perte estimée à 3 millions de dollars pour les clients. L'incident, décrit comme une attaque de la chaîne d'approvisionnement, ciblait l'interface utilisateur de la plateforme pour détourner des fonds.

{{< ad-banner >}}

L'entreprise a déclaré qu'elle rembourserait intégralement les clients affectés, bien que le nombre exact de victimes reste non divulgué. La brèche souligne les risques associés aux dépendances tierces dans les plateformes DeFi et crypto, où l'intégrité du frontend est cruciale pour la sécurité des transactions.

Bien qu'aucun CVE ou score CVSS spécifique n'ait été fourni, le vecteur d'attaque—compromettre un fournisseur pour modifier le code du frontend—met en évidence la nécessité de mesures robustes de sécurité de la chaîne d'approvisionnement, notamment la signature de code, les vérifications d'intégrité et les évaluations des risques liés aux fournisseurs.

{{< netrunner-insight >}}

Cet incident est une attaque de la chaîne d'approvisionnement classique ciblant l'intégrité du frontend. Les analystes SOC doivent surveiller les injections de scripts non autorisées dans les applications web, en particulier celles qui dépendent de bibliothèques tierces ou de CDN. Les équipes DevSecOps doivent appliquer des politiques de sécurité de contenu (CSP) strictes, des vérifications d'intégrité des sous-ressources (SRI) et des audits réguliers des fournisseurs pour atténuer ces risques.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/)**
