---
title: "Campagne Mini Shai-Hulud : Compromission des packages npm @antv via un compte de mainteneur"
date: "2026-05-19T10:37:35Z"
original_date: "2026-05-19T04:54:17"
lang: "fr"
translationKey: "mini-shai-hulud-campaign-compromises-antv-npm-packages-via-maintainer-account"
author: "NewsBot (Validated by Federico Sella)"
description: "Des attaquants compromettent le compte de mainteneur @antv 'atool' pour publier des packages npm malveillants, dont echarts-for-react avec 1,1 million de téléchargements hebdomadaires, dans le cadre de la vague d'attaques en cours sur la chaîne d'approvisionnement Mini Shai-Hulud."
original_url: "https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html"
source: "The Hacker News"
severity: "High"
target: "écosystème npm @antv"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Des attaquants compromettent le compte de mainteneur @antv 'atool' pour publier des packages npm malveillants, dont echarts-for-react avec 1,1 million de téléchargements hebdomadaires, dans le cadre de la vague d'attaques en cours sur la chaîne d'approvisionnement Mini Shai-Hulud.

{{< cyber-report severity="High" source="The Hacker News" target="écosystème npm @antv" >}}

Des chercheurs en cybersécurité ont identifié une nouvelle campagne d'attaque sur la chaîne d'approvisionnement logicielle ciblant l'écosystème npm @antv. Les attaquants ont compromis le compte de mainteneur npm 'atool' pour publier des versions malveillantes de plusieurs packages, dont echarts-for-react, un wrapper React largement utilisé pour Apache ECharts avec environ 1,1 million de téléchargements hebdomadaires.

{{< ad-banner >}}

Cette campagne fait partie de la vague d'attaques Mini Shai-Hulud en cours, qui a précédemment ciblé d'autres écosystèmes open-source. Les packages compromis contiennent probablement du code malveillant conçu pour exfiltrer des données sensibles ou établir des portes dérobées dans les environnements de développement.

Les organisations utilisant des packages @antv doivent immédiatement auditer leurs dépendances pour détecter des signes de compromission, faire pivoter les identifiants et examiner les modifications récentes dans leurs fichiers de verrouillage. L'étendue complète des packages affectés et la charge utile exacte font toujours l'objet d'une enquête.

{{< netrunner-insight >}}

Cette attaque souligne le besoin crucial de mesures de sécurité de la chaîne d'approvisionnement telles que la vérification de l'intégrité des packages, l'authentification multifacteur pour les comptes de mainteneur et l'analyse automatisée des dépendances. Les analystes SOC doivent prioriser la surveillance du trafic sortant anormal des pipelines de build, tandis que les équipes DevSecOps doivent imposer des contrôles d'accès stricts sur les comptes de publication de packages.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html)**
