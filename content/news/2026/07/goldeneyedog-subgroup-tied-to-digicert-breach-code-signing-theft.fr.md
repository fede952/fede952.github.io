---
title: "Sous-groupe GoldenEyeDog lié à la brèche de DigiCert et au vol de signature de code"
date: "2026-07-18T08:46:42Z"
original_date: "2026-07-17T16:39:16"
lang: "fr"
translationKey: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
slug: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "Des chercheurs attribuent l'incident d'avril 2026 chez DigiCert à CylindricalCanine, un sous-groupe du groupe de cybercriminalité chinois GoldenEyeDog, connu pour cibler les secteurs des jeux d'argent et du jeu vidéo."
original_url: "https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html"
source: "The Hacker News"
severity: "High"
target: "Infrastructure de signature de code de DigiCert"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Des chercheurs attribuent l'incident d'avril 2026 chez DigiCert à CylindricalCanine, un sous-groupe du groupe de cybercriminalité chinois GoldenEyeDog, connu pour cibler les secteurs des jeux d'argent et du jeu vidéo.

{{< cyber-report severity="High" source="The Hacker News" target="Infrastructure de signature de code de DigiCert" >}}

Des chercheurs en cybersécurité ont attribué l'incident de sécurité d'avril 2026 chez DigiCert à un groupe d'activités malveillantes nommé CylindricalCanine. Le groupe est décrit comme un sous-groupe de GoldenEyeDog (également connu sous les noms d'APT-Q-27, Dragon Breath et Miuuti Group), un groupe de cybercriminalité chinois qui cible historiquement les secteurs des jeux d'argent et du jeu vidéo.

{{< ad-banner >}}

La brèche a impliqué le vol de certificats de signature de code, ce qui pourrait permettre aux acteurs malveillants de signer des logiciels malveillants avec des identifiants légitimes, contournant ainsi les contrôles de sécurité. Expel a partagé des détails techniques de l'événement, soulignant la nature sophistiquée de l'opération.

Les organisations qui dépendent des certificats émis par DigiCert devraient examiner leurs inventaires de certificats et surveiller toute utilisation non autorisée. Cet incident souligne les risques posés par les attaques de la chaîne d'approvisionnement ciblant les autorités de certification de confiance.

{{< netrunner-insight >}}

Pour les analystes SOC : priorisez la surveillance des anomalies de signature de code et de l'utilisation inattendue de certificats. Les équipes DevSecOps devraient appliquer une gestion stricte du cycle de vie des certificats et envisager des certificats à courte durée de vie pour limiter l'exposition en cas de vol.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html)**
