---
title: "Le ver Miasma frappe 73 dépôts GitHub de Microsoft dans une attaque de la chaîne d'approvisionnement"
date: "2026-06-07T09:57:27Z"
original_date: "2026-06-06T06:58:04"
lang: "fr"
translationKey: "miasma-worm-hits-73-microsoft-github-repos-in-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Les dépôts GitHub de Microsoft, répartis dans Azure, Azure-Samples, Microsoft et MicrosoftDocs, ont été compromis par le ver auto-réplicant Miasma, impactant 73 dépôts."
original_url: "https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html"
source: "The Hacker News"
severity: "High"
target: "Dépôts GitHub de Microsoft"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Les dépôts GitHub de Microsoft, répartis dans Azure, Azure-Samples, Microsoft et MicrosoftDocs, ont été compromis par le ver auto-réplicant Miasma, impactant 73 dépôts.

{{< cyber-report severity="High" source="The Hacker News" target="Dépôts GitHub de Microsoft" >}}

La campagne d'attaque de la chaîne d'approvisionnement par le ver auto-réplicant Miasma s'est étendue pour cibler les dépôts GitHub de Microsoft, compromettant 73 dépôts dans quatre organisations : Azure, Azure-Samples, Microsoft et MicrosoftDocs. L'incident a été signalé par OpenSourceMalware, ce qui a incité GitHub à désactiver l'accès aux dépôts affectés pour contenir la propagation.

{{< ad-banner >}}

Cette attaque souligne la menace croissante des logiciels malveillants auto-réplicants dans les chaînes d'approvisionnement logicielles. En compromettant des dépôts de confiance, les attaquants peuvent injecter du code malveillant dans les projets en aval qui dépendent de ces sources, affectant potentiellement un large éventail d'utilisateurs et d'organisations.

Bien que les détails techniques spécifiques de la compromission restent confidentiels, cet incident met en évidence la nécessité de renforcer les mesures de sécurité dans les pipelines CI/CD et la gestion des dépôts. Les organisations devraient examiner leurs dépendances vis-à-vis des dépôts GitHub de Microsoft et surveiller toute activité anormale.

{{< netrunner-insight >}}

Pour les analystes SOC, priorisez la surveillance des commits ou des schémas d'accès inhabituels dans vos propres organisations GitHub. Les équipes DevSecOps doivent appliquer des règles strictes de protection des branches, exiger des commits signés et mettre en œuvre une analyse automatisée pour détecter les logiciels malveillants auto-réplicants dans les pipelines CI/CD. Cet incident rappelle brutalement que même les grands fournisseurs comme Microsoft ne sont pas à l'abri des attaques de la chaîne d'approvisionnement.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html)**
