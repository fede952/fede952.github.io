---
title: "Un contractant de la CISA fuit des clés AWS GovCloud sur GitHub"
date: "2026-05-19T10:35:27Z"
original_date: "2026-05-18T20:48:21"
lang: "fr"
translationKey: "cisa-contractor-leaks-aws-govcloud-keys-on-github"
author: "NewsBot (Validated by Federico Sella)"
description: "Un contractant de la CISA a exposé des identifiants AWS GovCloud et des détails internes de construction sur un dépôt GitHub public, marquant l'une des fuites de données gouvernementales les plus graves."
original_url: "https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/"
source: "Krebs on Security"
severity: "Critical"
target: "Comptes AWS GovCloud de la CISA"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un contractant de la CISA a exposé des identifiants AWS GovCloud et des détails internes de construction sur un dépôt GitHub public, marquant l'une des fuites de données gouvernementales les plus graves.

{{< cyber-report severity="Critical" source="Krebs on Security" target="Comptes AWS GovCloud de la CISA" >}}

Jusqu'à ce week-end, un contractant de la Cybersecurity & Infrastructure Security Agency (CISA) maintenait un dépôt GitHub public qui exposait des identifiants de plusieurs comptes AWS GovCloud hautement privilégiés et un grand nombre de systèmes internes de la CISA. Les experts en sécurité ont déclaré que l'archive publique comprenait des fichiers détaillant comment la CISA construit, teste et déploie des logiciels en interne, et qu'elle représente l'une des fuites de données gouvernementales les plus flagrantes de l'histoire récente.

{{< ad-banner >}}

Les identifiants exposés pourraient permettre à un attaquant d'accéder à des environnements cloud gouvernementaux sensibles et à des systèmes internes, conduisant potentiellement à une exfiltration de données ou à une compromission supplémentaire. Cet incident souligne les risques liés aux secrets codés en dur dans les dépôts publics, même par des contractants gouvernementaux.

{{< netrunner-insight >}}

Cette fuite met en évidence le besoin critique d'une analyse automatique des secrets et de contrôles d'accès stricts aux dépôts. Les analystes SOC doivent prioriser la surveillance des identifiants exposés dans les dépôts de code publics, tandis que les équipes DevSecOps doivent appliquer des politiques de gestion des secrets et faire immédiatement pivoter toute clé potentiellement compromise.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur Krebs on Security ›](https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/)**
