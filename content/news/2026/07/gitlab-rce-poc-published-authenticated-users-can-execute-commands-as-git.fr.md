---
title: "Publication d'un PoC RCE pour GitLab : les utilisateurs authentifiés peuvent exécuter des commandes en tant que git"
date: "2026-07-27T10:37:15Z"
original_date: "2026-07-25T10:14:26"
lang: "fr"
translationKey: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
slug: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
author: "NewsBot (Validated by Federico Sella)"
description: "Un exploit de preuve de concept pour une faille d'exécution de code à distance dans GitLab a été publié, ciblant les serveurs auto-hébergés 18.11.3 non patchés. Les utilisateurs authentifiés peuvent exécuter des commandes en tant qu'utilisateur git."
original_url: "https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html"
source: "The Hacker News"
severity: "High"
target: "GitLab self-managed 18.11.3"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un exploit de preuve de concept pour une faille d'exécution de code à distance dans GitLab a été publié, ciblant les serveurs auto-hébergés 18.11.3 non patchés. Les utilisateurs authentifiés peuvent exécuter des commandes en tant qu'utilisateur git.

{{< cyber-report severity="High" source="The Hacker News" target="GitLab self-managed 18.11.3" >}}

Le 24 juillet 2026, des chercheurs en sécurité chez depthfirst ont publié un exploit de preuve de concept fonctionnel pour une vulnérabilité d'exécution de code à distance dans GitLab. Cette faille, corrigée par GitLab le 10 juin 2026, permet à tout utilisateur authentifié disposant d'un accès push à un projet d'exécuter des commandes arbitraires en tant qu'utilisateur git sur les serveurs GitLab auto-hébergés 18.11.3 n'ayant pas appliqué la mise à jour.

{{< ad-banner >}}

L'exploit utilise un notebook Jupyter malveillant commité dans un projet. Lorsque l'attaquant ouvre le diff du commit, le notebook malveillant déclenche une fuite de tas, permettant l'exécution de commandes. Cette technique contourne les contrôles d'authentification typiques et ne nécessite aucun privilège spécial au-delà de l'accès standard au projet.

Les organisations utilisant des instances GitLab auto-hébergées doivent immédiatement vérifier qu'elles ont appliqué le correctif du 10 juin. La disponibilité publique du code d'exploit augmente le risque d'exploitation active, en particulier pour les instances exposées à Internet. Les équipes bleues doivent surveiller les commits de notebooks Jupyter inhabituels et toute activité inattendue de l'utilisateur git.

{{< netrunner-insight >}}

Cet exploit souligne le danger des correctifs retardés dans les plateformes CI/CD auto-hébergées. Les analystes SOC doivent prioriser la détection des processus git anormaux et des téléchargements inattendus de notebooks Jupyter. Les équipes DevSecOps doivent imposer une fenêtre de correction stricte pour GitLab et envisager une segmentation réseau pour limiter l'exposition des instances auto-hébergées.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)**
