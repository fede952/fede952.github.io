---
title: "CISA ajoute une faille RCE de PTC Windchill à son catalogue KEV en raison d'attaques actives par web shell"
date: "2026-06-27T09:25:09Z"
original_date: "2026-06-26T12:31:56"
lang: "fr"
translationKey: "cisa-adds-ptc-windchill-rce-flaw-to-kev-amid-active-web-shell-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA ajoute une vulnérabilité critique d'exécution de code à distance dans PTC Windchill PDMlink et FlexPLM à son catalogue de vulnérabilités exploitées connues en raison d'une exploitation active."
original_url: "https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html"
source: "The Hacker News"
severity: "Critical"
target: "PTC Windchill PDMlink et FlexPLM"
cve: null
cvss: null
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA ajoute une vulnérabilité critique d'exécution de code à distance dans PTC Windchill PDMlink et FlexPLM à son catalogue de vulnérabilités exploitées connues en raison d'une exploitation active.

{{< cyber-report severity="Critical" source="The Hacker News" target="PTC Windchill PDMlink et FlexPLM" kev="true" >}}

La Cybersecurity and Infrastructure Security Agency (CISA) des États-Unis a ajouté une vulnérabilité critique d'exécution de code à distance affectant PTC Windchill PDMlink et PTC FlexPLM à son catalogue de vulnérabilités exploitées connues (KEV). Cette décision fait suite à des preuves d'exploitation active, avec des rapports indiquant des attaques par web shell en cours ciblant ces systèmes d'entreprise de gestion de données produit (PDM) et de gestion du cycle de vie des produits (PLM).

{{< ad-banner >}}

Bien que l'identifiant CVE spécifique n'ait pas été divulgué dans l'annonce, la vulnérabilité est décrite comme une faille RCE critique qui pourrait permettre aux attaquants d'exécuter du code arbitraire sur les systèmes affectés. Les organisations utilisant ces produits sont invitées à prioriser l'application des correctifs et à examiner leurs environnements pour détecter des signes de compromission, car l'exploitation peut entraîner une prise de contrôle complète du système.

Le catalogue KEV de la CISA sert de directive opérationnelle contraignante pour les agences fédérales, exigeant une remédiation dans des délais spécifiés. Les organisations du secteur privé sont fortement invitées à considérer cette menace comme hautement prioritaire et à mettre en œuvre des mesures d'atténuation telles que la segmentation du réseau et la surveillance des activités anormales de web shell.

{{< netrunner-insight >}}

Pour les analystes SOC, priorisez la recherche d'indicateurs de web shell sur les serveurs Windchill exposés—recherchez des processus enfants inhabituels générés par l'application ou des connexions sortantes vers des IP inconnues. Les équipes DevSecOps doivent immédiatement appliquer les correctifs disponibles et envisager de déployer des correctifs virtuels ou des règles WAF si le correctif est retardé. Cela rappelle que les systèmes PLM, souvent négligés dans la gestion des correctifs, sont des cibles attrayantes pour les groupes de ransomware.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html)**
