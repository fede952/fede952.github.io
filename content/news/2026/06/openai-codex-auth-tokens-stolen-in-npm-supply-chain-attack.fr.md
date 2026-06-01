---
title: "Vol de jetons d'authentification OpenAI Codex lors d'une attaque sur la chaîne d'approvisionnement npm"
date: "2026-06-01T12:34:23Z"
original_date: "2026-06-01T09:31:15"
lang: "fr"
translationKey: "openai-codex-auth-tokens-stolen-in-npm-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Le paquet npm malveillant codexui-android cible les développeurs, volant les jetons d'authentification OpenAI Codex avec plus de 29 000 téléchargements hebdomadaires."
original_url: "https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html"
source: "The Hacker News"
severity: "High"
target: "Développeurs OpenAI Codex"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Le paquet npm malveillant codexui-android cible les développeurs, volant les jetons d'authentification OpenAI Codex avec plus de 29 000 téléchargements hebdomadaires.

{{< cyber-report severity="High" source="The Hacker News" target="Développeurs OpenAI Codex" >}}

Des chercheurs en cybersécurité ont découvert une campagne malveillante sur la chaîne d'approvisionnement ciblant les développeurs utilisant OpenAI Codex. L'attaque exploite un paquet npm d'apparence légitime nommé codexui-android, présenté comme une interface web distante pour OpenAI Codex à la fois sur GitHub et npm. Le paquet a attiré plus de 29 000 téléchargements hebdomadaires, indiquant une portée significative au sein de la communauté des développeurs.

{{< ad-banner >}}

Le paquet malveillant est conçu pour voler les jetons d'authentification OpenAI Codex des développeurs peu méfiants. Selon le rapport, le paquet reste disponible au téléchargement, constituant une menace persistante. Les développeurs ayant installé codexui-android sont invités à renouveler immédiatement leurs jetons et à auditer leurs systèmes pour détecter tout accès non autorisé.

Cet incident met en lumière le risque persistant des attaques sur la chaîne d'approvisionnement dans l'écosystème open source. L'utilisation de noms de paquets à consonance légitime et des nombres de téléchargements élevés peuvent endormir la vigilance des développeurs. Les organisations devraient mettre en œuvre des processus stricts de vérification des paquets et envisager d'utiliser des outils capables de détecter les comportements anormaux des paquets.

{{< netrunner-insight >}}

Pour les analystes SOC et les ingénieurs DevSecOps, cette attaque souligne la nécessité de surveiller les téléchargements et le comportement des paquets npm. Mettez en œuvre une détection en temps réel pour l'exfiltration inattendue de jetons et appliquez le principe du moindre privilège pour les jetons API. Auditez régulièrement votre chaîne d'approvisionnement logicielle et envisagez d'utiliser des outils de vérification de l'intégrité des paquets.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html)**
