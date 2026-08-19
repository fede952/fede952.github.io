---
title: "Des paquets RubyGems typosquattés volent les identifiants de navigateur et les portefeuilles de cryptomonnaies"
date: "2026-08-19T07:36:21Z"
original_date: "2026-08-18T11:20:00"
lang: "fr"
translationKey: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
slug: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
author: "NewsBot (Validated by Federico Sella)"
description: "Des chercheurs signalent 16 paquets RubyGems typosquattés qui déploient un voleur d'informations basé sur Windows, ciblant les identifiants de navigateur et les portefeuilles de cryptomonnaies."
original_url: "https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html"
source: "The Hacker News"
severity: "High"
target: "Utilisateurs de RubyGems sous Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Des chercheurs signalent 16 paquets RubyGems typosquattés qui déploient un voleur d'informations basé sur Windows, ciblant les identifiants de navigateur et les portefeuilles de cryptomonnaies.

{{< cyber-report severity="High" source="The Hacker News" target="Utilisateurs de RubyGems sous Windows" >}}

Des chercheurs en cybersécurité ont découvert une nouvelle campagne de typosquattage ciblant les utilisateurs de RubyGems, déployant un voleur d'informations basé sur Windows. La campagne, suivie sous le nom de StubMaker, a été découverte le 15 août 2026 par OpenSourceMalware, et implique 16 paquets malveillants conçus pour voler les identifiants de navigateur et les portefeuilles de cryptomonnaies.

{{< ad-banner >}}

Les paquets malveillants, qui incluent des noms comme 'ubnuler', 'ubnlder', 'ri18nr', 'reaker', 'rakier', 'orakw' et 'joxn', sont probablement des typosquats de gems populaires, trompant les développeurs pour qu'ils les installent. Une fois installés, le voleur récupère des données sensibles à partir des navigateurs et des extensions de portefeuille de cryptomonnaies, posant un risque significatif pour la chaîne d'approvisionnement.

Cette campagne met en évidence la menace persistante du typosquattage dans les écosystèmes open source. Les développeurs sont invités à vérifier soigneusement les noms des paquets, à utiliser des sources fiables et à surveiller les dépendances suspectes dans leurs projets.

{{< netrunner-insight >}}

Pour les analystes SOC, cette campagne souligne la nécessité de surveiller les installations RubyGems inattendues et les appels réseau vers des domaines suspects. Les ingénieurs DevSecOps devraient imposer un épinglage strict des dépendances et utiliser des outils qui analysent les paquets typosquattés. De plus, envisagez de bloquer les noms de paquets malveillants connus et d'éduquer les développeurs sur les risques de typosquattage.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html)**
