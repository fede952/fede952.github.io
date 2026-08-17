---
title: "Versions malveillantes de LiteLLM sur PyPI liées au piratage de Trivy exposent plus de 2 100 organisations"
date: "2026-08-17T07:48:06Z"
original_date: "2026-08-12T08:04:52"
lang: "fr"
translationKey: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
slug: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
author: "NewsBot (Validated by Federico Sella)"
description: "Deux paquets LiteLLM malveillants sur PyPI ont volé des clés cloud, des clés SSH, et plus encore. Les données de CloudSEK suggèrent que plus de 2 100 organisations pourraient être exposées."
original_url: "https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html"
source: "The Hacker News"
severity: "High"
target: "Utilisateurs de LiteLLM sur PyPI"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Deux paquets LiteLLM malveillants sur PyPI ont volé des clés cloud, des clés SSH, et plus encore. Les données de CloudSEK suggèrent que plus de 2 100 organisations pourraient être exposées.

{{< cyber-report severity="High" source="The Hacker News" target="Utilisateurs de LiteLLM sur PyPI" >}}

Deux versions malveillantes de LiteLLM ont été publiées sur PyPI et sont restées disponibles pendant environ 40 minutes en mars. Ces paquets contenaient du code de vol d'informations conçu pour collecter un large éventail de secrets, notamment des clés d'accès cloud, des clés privées SSH, des jetons Kubernetes et des mots de passe de bases de données sur tout système les ayant installés.

{{< ad-banner >}}

La société de renseignement sur les menaces CloudSEK a obtenu un ensemble de données constitué d'environ 434 000 fichiers capturés par les attaquants. L'analyse de ces données suggère que l'exposition pourrait affecter plus de 2 100 organisations, soulignant l'ampleur potentielle de la compromission.

L'incident est lié au piratage antérieur de Trivy, indiquant une attaque coordonnée de la chaîne d'approvisionnement. Les organisations ayant installé LiteLLM depuis PyPI pendant la fenêtre concernée doivent immédiatement faire pivoter toutes les informations d'identification exposées et enquêter sur les signes d'accès non autorisé.

{{< netrunner-insight >}}

Cet incident souligne la nécessité cruciale d'une vigilance dans la chaîne d'approvisionnement logicielle. Les analystes SOC doivent surveiller toute installation des versions malveillantes de LiteLLM et prioriser la rotation des informations d'identification pour tout secret potentiellement exposé. Les équipes DevSecOps doivent appliquer des contrôles stricts d'intégrité des paquets et envisager d'utiliser des miroirs privés ou des fichiers de verrouillage avec des hachages pour atténuer ces risques.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html)**
