---
title: "Une fuite de données chez KDDI expose 14,2 millions d'identifiants de messagerie sur six FAI"
date: "2026-06-29T11:56:07Z"
original_date: "2026-06-28T14:13:46"
lang: "fr"
translationKey: "kddi-data-breach-exposes-14-2-million-email-logins-across-six-isps"
author: "NewsBot (Validated by Federico Sella)"
description: "L'opérateur télécom japonais KDDI révèle une intrusion dans son système de messagerie affectant cinq autres FAI, compromettant jusqu'à 14,2 millions d'identifiants utilisateurs."
original_url: "https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/"
source: "BleepingComputer"
severity: "High"
target: "Systèmes de messagerie des FAI japonais"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

L'opérateur télécom japonais KDDI révèle une intrusion dans son système de messagerie affectant cinq autres FAI, compromettant jusqu'à 14,2 millions d'identifiants utilisateurs.

{{< cyber-report severity="High" source="BleepingComputer" target="Systèmes de messagerie des FAI japonais" >}}

L'opérateur de télécommunications japonais KDDI Corporation a divulgué une fuite de données dans laquelle des acteurs malveillants ont accédé à l'un de ses systèmes de messagerie utilisé par cinq autres fournisseurs d'accès Internet (FAI) du pays. La fuite a potentiellement exposé jusqu'à 14,2 millions d'identifiants de messagerie, impactant un nombre significatif d'utilisateurs chez plusieurs fournisseurs.

{{< ad-banner >}}

Le système compromis fait partie de l'infrastructure de messagerie de KDDI, qui sert de backend pour plusieurs FAI. Bien que la méthode exacte d'intrusion n'ait pas été détaillée, cet incident souligne les risques inhérents aux architectures de services partagés, où un point de défaillance unique peut se répercuter sur plusieurs organisations.

KDDI a informé les FAI concernés et travaille à contenir la fuite. Les utilisateurs sont invités à changer leurs mots de passe et à activer l'authentification multifacteur lorsque c'est possible. Cet incident met en évidence la nécessité d'une segmentation robuste et d'une surveillance des composants d'infrastructure partagés.

{{< netrunner-insight >}}

Cette fuite est un exemple typique de risque lié à la chaîne d'approvisionnement dans les écosystèmes de FAI. Les analystes SOC doivent prioriser la surveillance des mouvements latéraux des systèmes de messagerie vers d'autres actifs critiques, tandis que les équipes DevSecOps doivent imposer une segmentation réseau stricte et un accès au moindre privilège pour les services backend partagés. Attendez-vous à des attaques de bourrage d'identifiants ciblant ces comptes exposés dans les semaines à venir.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/)**
