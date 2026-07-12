---
title: "Fausse inscription de clé d'accès Microsoft Entra ciblant les utilisateurs M365 dans une campagne d'extorsion de données"
date: "2026-07-12T09:00:42Z"
original_date: "2026-07-10T10:30:20"
lang: "fr"
translationKey: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
slug: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "L'acteur malveillant O-UNC-066 utilise le phishing vocal pour inciter les utilisateurs à inscrire une fausse clé d'accès Entra, visant à compromettre les comptes Microsoft 365 pour une extorsion de données."
original_url: "https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html"
source: "The Hacker News"
severity: "High"
target: "Utilisateurs de Microsoft 365"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

L'acteur malveillant O-UNC-066 utilise le phishing vocal pour inciter les utilisateurs à inscrire une fausse clé d'accès Entra, visant à compromettre les comptes Microsoft 365 pour une extorsion de données.

{{< cyber-report severity="High" source="The Hacker News" target="Utilisateurs de Microsoft 365" >}}

Un acteur malveillant suivi sous le nom O-UNC-066 par Okta a été observé menant des attaques de phishing vocal ciblant les utilisateurs de Microsoft 365 dans plusieurs secteurs. Les attaquants se font passer pour des demandes de sécurité légitimes afin de tromper les victimes et les inciter à inscrire une fausse clé d'accès Entra, accordant ainsi à l'adversaire un accès non autorisé à leurs comptes.

{{< ad-banner >}}

La campagne utilise un kit de phishing contrôlé par panneau spécialement conçu pour intercepter le processus d'inscription de la clé d'accès. Une fois que l'attaquant obtient l'accès, il cherche à mener une extorsion de données, en exfiltrant des informations sensibles et en exigeant une rançon. Les attaques mettent en évidence une tendance croissante à utiliser les canaux vocaux pour contourner les défenses traditionnelles de phishing par e-mail.

Il est conseillé aux organisations de mettre en œuvre une authentification multifacteur (MFA) avec des clés de sécurité matérielles et de former les utilisateurs à vérifier toute demande de sécurité non sollicitée via des canaux de communication alternatifs. La surveillance des activités d'inscription de clés d'accès anormales peut aider à détecter ces attaques précocement.

{{< netrunner-insight >}}

Cette attaque souligne l'importance de traiter les demandes de sécurité vocales avec le même scepticisme que les e-mails de phishing. Les analystes SOC doivent surveiller les tentatives d'inscription de clés d'accès inhabituelles et s'assurer que les processus d'inscription MFA nécessitent une vérification hors bande. Les équipes DevSecOps devraient envisager de mettre en œuvre des politiques d'accès conditionnel qui limitent l'inscription des clés d'accès aux appareils et emplacements de confiance.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html)**
