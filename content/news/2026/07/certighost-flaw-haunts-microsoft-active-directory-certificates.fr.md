---
title: "La faille 'Certighost' hante les certificats Microsoft Active Directory"
date: "2026-07-29T09:36:19Z"
original_date: "2026-07-28T16:38:48"
lang: "fr"
translationKey: "certighost-flaw-haunts-microsoft-active-directory-certificates"
slug: "certighost-flaw-haunts-microsoft-active-directory-certificates"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft a corrigé une vulnérabilité de haute sévérité permettant une élévation de privilèges dans les environnements Active Directory. Les analystes SOC devraient prioriser le déploiement du correctif."
original_url: "https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates"
source: "Dark Reading"
severity: "High"
target: "Microsoft Active Directory Certificate Services"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft a corrigé une vulnérabilité de haute sévérité permettant une élévation de privilèges dans les environnements Active Directory. Les analystes SOC devraient prioriser le déploiement du correctif.

{{< cyber-report severity="High" source="Dark Reading" target="Microsoft Active Directory Certificate Services" >}}

Microsoft a corrigé une vulnérabilité de haute sévérité dans Active Directory Certificate Services, surnommée 'Certighost', qui pourrait permettre à un attaquant d'élever ses privilèges et de compromettre un environnement Active Directory. La faille a été divulguée par Dark Reading le 28 juillet 2026.

{{< ad-banner >}}

La vulnérabilité affecte le processus d'inscription des certificats, permettant à un acteur malveillant disposant d'un accès de bas niveau d'élever ses privilèges jusqu'à celui d'administrateur de domaine. Cela pourrait entraîner une compromission totale de l'infrastructure AD, y compris la capacité de forger des certificats et d'usurper l'identité de tout utilisateur ou appareil.

Les organisations utilisant Microsoft Active Directory Certificate Services sont invitées à appliquer immédiatement les dernières mises à jour de sécurité. Cette vulnérabilité souligne le caractère critique des services de certificats pour maintenir la confiance dans les environnements AD.

{{< netrunner-insight >}}

C'est un vecteur d'attaque classique contre les services de certificats AD. Assurez-vous que vos modèles de certificats sont durcis et que les autorisations d'inscription sont strictement contrôlées. Corrigez immédiatement et surveillez les demandes de certificats inhabituelles ou les élévations de privilèges.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur Dark Reading ›](https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates)**
