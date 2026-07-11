---
title: "Nouveau RAT MODBEACON utilise le streaming gRPC pour le trafic C2 chiffré"
date: "2026-07-11T08:43:59Z"
original_date: "2026-07-10T13:15:23"
lang: "fr"
translationKey: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
slug: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Le groupe Silver Fox lié à la Chine déploie le RAT MODBEACON basé sur Rust via l'empoisonnement SEO, utilisant le streaming gRPC pour la communication C2 chiffrée."
original_url: "https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html"
source: "The Hacker News"
severity: "High"
target: "Utilisateurs Windows via des installateurs contrefaits"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Le groupe Silver Fox lié à la Chine déploie le RAT MODBEACON basé sur Rust via l'empoisonnement SEO, utilisant le streaming gRPC pour la communication C2 chiffrée.

{{< cyber-report severity="High" source="The Hacker News" target="Utilisateurs Windows via des installateurs contrefaits" >}}

Le groupe de cybercriminalité Silver Fox, lié à la Chine, a été attribué à un nouveau cheval de Troie d'accès à distance (RAT) basé sur Rust appelé MODBEACON. Le malware utilise le streaming gRPC pour le trafic de commande et contrôle (C2) chiffré, rendant la détection plus difficile.

{{< ad-banner >}}

Selon la société chinoise de cybersécurité QiAnXin, Silver Fox propage MODBEACON via des installateurs contrefaits utilisant des techniques d'empoisonnement SEO. Bien que le groupe puisse sembler être une opération de faible sophistication mais très active, leurs véritables capacités organisationnelles sont plus avancées.

L'utilisation du streaming gRPC pour la communication C2 représente une technique novatrice pour les malwares, car elle exploite HTTP/2 et les buffers de protocole pour se fondre dans le trafic légitime. Les équipes de sécurité doivent surveiller le trafic gRPC inhabituel et enquêter sur les sites de téléchargement empoisonnés par SEO.

{{< netrunner-insight >}}

Les analystes SOC devraient ajouter l'analyse du trafic gRPC à leurs pipelines de détection, car l'utilisation de RPC streaming par MODBEACON peut contourner les signatures réseau traditionnelles. Les équipes DevSecOps doivent vérifier l'intégrité des téléchargements de logiciels et envisager de bloquer les domaines d'empoisonnement SEO connus. Ce RAT souligne la nécessité d'une chasse proactive aux menaces contre les malwares basés sur Rust.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html)**
