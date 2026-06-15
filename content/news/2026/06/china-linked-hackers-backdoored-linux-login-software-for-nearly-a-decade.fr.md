---
title: "Des pirates liés à la Chine ont dissimulé une porte dérobée dans un logiciel de connexion Linux pendant près d'une décennie"
date: "2026-06-15T13:04:59Z"
original_date: "2026-06-12T18:17:55"
lang: "fr"
translationKey: "china-linked-hackers-backdoored-linux-login-software-for-nearly-a-decade"
author: "NewsBot (Validated by Federico Sella)"
description: "Un groupe lié à la Chine, connu sous le nom de Velvet Ant, a compromis les composants PAM et OpenSSH, se cachant dans les systèmes de connexion Linux pendant près de dix ans sans être détecté."
original_url: "https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html"
source: "The Hacker News"
severity: "High"
target: "Systèmes de connexion Linux (PAM, OpenSSH)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un groupe lié à la Chine, connu sous le nom de Velvet Ant, a compromis les composants PAM et OpenSSH, se cachant dans les systèmes de connexion Linux pendant près de dix ans sans être détecté.

{{< cyber-report severity="High" source="The Hacker News" target="Systèmes de connexion Linux (PAM, OpenSSH)" >}}

Un acteur de menace lié à la Chine, suivi sous le nom de Velvet Ant, a été découvert comme ayant dissimulé une porte dérobée dans des composants Linux essentiels à la connexion, notamment PAM (Pluggable Authentication Modules) et OpenSSH, leur permettant de maintenir un accès persistant pendant près d'une décennie. Le groupe a ciblé un réseau où ils ont intégré leur porte dérobée profondément dans la pile d'authentification, la rendant résistante aux procédures de nettoyage standard.

{{< ad-banner >}}

Selon la société de sécurité Sygnia, les attaquants ont exploité la confiance accordée aux logiciels de connexion pour échapper à la détection. En modifiant les mécanismes mêmes qui contrôlent l'accès des utilisateurs, ils ont assuré que leur point d'appui survivait aux mises à jour système et aux analyses de sécurité de routine. Cette campagne met en lumière la sophistication croissante des groupes parrainés par des États dans le ciblage des infrastructures fondamentales.

Cette compromission souligne la nécessité pour les organisations de surveiller l'intégrité des composants système critiques au-delà de la détection classique des points d'extrémité. Les défenseurs devraient envisager une surveillance de l'intégrité des fichiers pour les modules PAM et les binaires SSH, ainsi qu'une analyse comportementale des journaux d'authentification pour repérer les anomalies indiquant des processus de connexion compromis.

{{< netrunner-insight >}}

Pour les analystes SOC et les équipes DevSecOps, c'est un rappel frappant que les attaquants ciblent la couche d'authentification elle-même. Mettez en œuvre des contrôles d'intégrité en temps réel sur les binaires PAM et OpenSSH, et envisagez d'utiliser une surveillance au niveau du noyau pour détecter les altérations. De plus, examinez les modifications de l'authentification par clé SSH et de la configuration PAM dans le cadre de vos playbooks de réponse aux incidents.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html)**
