---
title: "Fuite GitHub de la CISA : des clés AWS GovCloud exposées pendant six mois"
date: "2026-07-14T09:01:14Z"
original_date: "2026-07-13T15:03:28"
lang: "fr"
translationKey: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
slug: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
author: "NewsBot (Validated by Federico Sella)"
description: "Un sous-traitant a divulgué des identifiants internes de la CISA, dont des clés AWS GovCloud, sur GitHub pendant six mois. Les experts soulignent des leçons cruciales pour les équipes de sécurité."
original_url: "https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/"
source: "Krebs on Security"
severity: "High"
target: "dépôt GitHub de la CISA"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un sous-traitant a divulgué des identifiants internes de la CISA, dont des clés AWS GovCloud, sur GitHub pendant six mois. Les experts soulignent des leçons cruciales pour les équipes de sécurité.

{{< cyber-report severity="High" source="Krebs on Security" target="dépôt GitHub de la CISA" >}}

La Cybersecurity and Infrastructure Security Agency (CISA) a révélé une fuite de données où un sous-traitant a publié par inadvertance des dizaines d'identifiants internes, dont des clés AWS GovCloud, dans un dépôt GitHub public. Les identifiants sont restés exposés pendant près de six mois avant que KrebsOnSecurity n'en informe l'agence.

{{< ad-banner >}}

Le rapport d'incident de la CISA a identifié des lacunes dans leur réponse initiale, comme une détection tardive et l'absence d'analyse automatisée des secrets dans les dépôts publics. L'incident souligne la nécessité d'une gestion robuste des secrets et d'une surveillance continue des dépôts de code.

Les experts recommandent de mettre en œuvre des hooks de pré-commit, une analyse régulière des secrets et des contrôles d'accès stricts pour éviter des fuites similaires. L'utilisation d'identifiants éphémères et d'une rotation automatisée peut également atténuer l'impact des clés exposées.

{{< netrunner-insight >}}

Cet incident est un cas d'école démontrant pourquoi l'analyse des secrets doit être intégrée dans les pipelines CI/CD, et pas seulement après le commit. Les analystes SOC doivent prioriser les alertes pour les expositions de dépôts publics, et les équipes DevSecOps doivent imposer un accès au moindre privilège pour les sous-traitants. Automatisez la rotation des identifiants et envisagez d'utiliser des outils comme GitLeaks ou TruffleHog pour détecter les fuites tôt.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur Krebs on Security ›](https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/)**
