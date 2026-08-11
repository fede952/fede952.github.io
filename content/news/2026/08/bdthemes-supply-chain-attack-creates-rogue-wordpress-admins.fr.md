---
title: "Attaque de la chaîne d'approvisionnement de BdThemes crée des administrateurs WordPress malveillants"
date: "2026-08-11T08:10:19Z"
original_date: "2026-08-11T05:48:44"
lang: "fr"
translationKey: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
slug: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
author: "NewsBot (Validated by Federico Sella)"
description: "Une compromission de la chaîne d'approvisionnement frappe les plugins WordPress de BdThemes ; aucun code source modifié, mais un JSON malveillant crée des comptes administrateurs frauduleux."
original_url: "https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html"
source: "The Hacker News"
severity: "High"
target: "Sites WordPress utilisant les plugins BdThemes"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Une compromission de la chaîne d'approvisionnement frappe les plugins WordPress de BdThemes ; aucun code source modifié, mais un JSON malveillant crée des comptes administrateurs frauduleux.

{{< cyber-report severity="High" source="The Hacker News" target="Sites WordPress utilisant les plugins BdThemes" >}}

Des chercheurs en cybersécurité ont révélé une attaque de la chaîne d'approvisionnement ciblant BdThemes, un fournisseur de plugins WordPress. La compromission a conduit à la désactivation temporaire des téléchargements de plugins par l'équipe des plugins WordPress. Notamment, l'attaque s'écarte des incidents typiques de chaîne d'approvisionnement : aucun fichier de code source dans le dépôt officiel de WordPress.org n'a été modifié.

{{< ad-banner >}}

Au lieu de cela, l'attaque exploite des charges utiles JSON malveillantes pour créer des comptes administrateurs WordPress frauduleux. Cette technique permet aux attaquants d'obtenir un accès non autorisé aux sites concernés sans modifier les fichiers principaux des plugins, rendant la détection plus difficile pour les contrôles d'intégrité standard.

Le chercheur de Wordfence, Paolo Tresso, a souligné la nature inhabituelle de l'attaque, insistant sur le fait que l'absence de modifications du code source souligne la nécessité d'une surveillance complète de la chaîne d'approvisionnement au-delà de la seule intégrité du code.

{{< netrunner-insight >}}

Cette attaque souligne l'importance de surveiller non seulement les modifications de code, mais aussi les fichiers de configuration et de données comme JSON. Pour les analystes SOC, traitez les mises à jour de plugins comme des événements à haut risque et vérifiez l'intégrité de tous les fichiers, pas seulement le code source. DevSecOps devrait mettre en œuvre une surveillance en temps réel pour la création inattendue de comptes administrateurs et envisager une surveillance de l'intégrité des fichiers couvrant les actifs non liés au code.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html)**
