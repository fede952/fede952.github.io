---
title: "Les attaques CSS franchissent les limites des e-mails pour voler mots de passe et jetons"
date: "2026-08-09T07:52:16Z"
original_date: "2026-08-08T08:03:57"
lang: "fr"
translationKey: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
slug: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "De nouvelles recherches révèlent des attaques basées sur CSS qui sortent du contenu des e-mails pour détourner les interfaces de webmail, volant identifiants et jetons chez les principaux fournisseurs."
original_url: "https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html"
source: "The Hacker News"
severity: "High"
target: "Interfaces de webmail (Outlook, Gmail, etc.)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

De nouvelles recherches révèlent des attaques basées sur CSS qui sortent du contenu des e-mails pour détourner les interfaces de webmail, volant identifiants et jetons chez les principaux fournisseurs.

{{< cyber-report severity="High" source="The Hacker News" target="Interfaces de webmail (Outlook, Gmail, etc.)" >}}

Le chercheur en sécurité Gareth de PortSwigger a découvert une nouvelle classe d'attaques qui exploitent CSS pour briser l'isolation prévue entre le contenu des e-mails et l'interface de webmail environnante. En élaborant des e-mails malveillants, un attaquant peut faire sortir le contenu de sa limite de message et interférer avec l'interface utilisateur du webmail, pouvant capturer des mots de passe, voler des jetons de session et détourner des actions utilisateur de confiance.

{{< ad-banner >}}

La recherche démontre des chaînes d'attaque affectant les principaux fournisseurs de webmail, notamment Outlook, Gmail, Fastmail, Proton Mail, Yahoo Mail et AOL Mail. Au-delà du vol d'identifiants, les techniques peuvent être utilisées pour prendre le contrôle de comptes tiers, fuiter des jetons sensibles et même manipuler des outils d'IA qui lisent les e-mails, élargissant considérablement la surface d'attaque.

Ces résultats mettent en évidence une faiblesse fondamentale dans la manière dont les clients de webmail rendent le contenu non fiable. Bien qu'aucun CVE spécifique n'ait encore été attribué, l'impact est grave, et les organisations qui dépendent du webmail devraient surveiller les mises à jour et envisager des couches de sécurité supplémentaires pour atténuer une exploitation potentielle.

{{< netrunner-insight >}}

Cette recherche souligne que l'e-mail n'est pas seulement un vecteur de malware, mais peut aussi être une arme contre l'interface même à laquelle les utilisateurs font confiance. Les analystes SOC devraient traiter les e-mails suspects comme des charges utiles capables de briser l'interface, et non seulement comme des appâts de phishing. Les équipes DevSecOps devraient examiner comment leurs clients de webmail isolent le contenu et envisager d'appliquer des en-têtes de politique de sécurité du contenu (CSP) stricts pour limiter les tentatives d'évasion basées sur CSS.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html)**
