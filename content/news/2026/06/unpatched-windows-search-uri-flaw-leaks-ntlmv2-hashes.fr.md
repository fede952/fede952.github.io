---
title: "Une faille non corrigée dans le gestionnaire d'URI de recherche Windows expose les hachages NTLMv2"
date: "2026-06-03T11:53:18Z"
original_date: "2026-06-03T10:18:52"
lang: "fr"
translationKey: "unpatched-windows-search-uri-flaw-leaks-ntlmv2-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "Des chercheurs divulguent une vulnérabilité non corrigée dans le gestionnaire d'URI search: de Windows qui peut exposer les hachages NTLMv2, similaire à la faille CVE-2026-33829 de l'outil de capture d'écran."
original_url: "https://thehackernews.com/2026/06/unpatched-windows-search-uri.html"
source: "The Hacker News"
severity: "High"
target: "Gestionnaire d'URI search: de Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Des chercheurs divulguent une vulnérabilité non corrigée dans le gestionnaire d'URI search: de Windows qui peut exposer les hachages NTLMv2, similaire à la faille CVE-2026-33829 de l'outil de capture d'écran.

{{< cyber-report severity="High" source="The Hacker News" target="Gestionnaire d'URI search: de Windows" >}}

Des chercheurs en cybersécurité de Huntress ont divulgué les détails d'une vulnérabilité non corrigée dans le gestionnaire d'URI search: de Windows qui pourrait permettre à des attaquants de voler des hachages NTLMv2. Le problème rappelle CVE-2026-33829, une vulnérabilité d'usurpation dans le gestionnaire d'URI ms-screensketch: de l'outil de capture d'écran Windows qui exposait également des hachages NTLM.

{{< ad-banner >}}

La faille nouvellement identifiée réside dans le schéma d'URI search:, utilisé pour lancer des recherches Windows. En créant un lien ou un fichier malveillant qui déclenche le gestionnaire d'URI search:, un attaquant peut forcer le système cible à s'authentifier auprès d'un serveur distant, divulguant ainsi le hachage NTLMv2 de l'utilisateur. Ce hachage peut ensuite être craqué hors ligne ou utilisé dans des attaques de relais.

À la date de publication, aucun correctif officiel n'a été publié par Microsoft. Les organisations sont invitées à surveiller les mises à jour et à envisager de bloquer le gestionnaire d'URI search: via une stratégie de groupe ou des outils de sécurité des terminaux jusqu'à ce qu'un correctif soit disponible.

{{< netrunner-insight >}}

C'est un vecteur de relais NTLM classique que les analystes SOC doivent surveiller dans les journaux d'authentification. Les ingénieurs DevSecOps doivent immédiatement examiner toute utilisation de gestionnaires d'URI dans leurs environnements et envisager d'appliquer des mesures d'atténuation comme la désactivation de NTLMv2 ou l'application de la signature SMB. Jusqu'à ce que Microsoft corrige cela, considérez que l'URI search: est un point d'entrée potentiel pour le vol d'identifiants.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/06/unpatched-windows-search-uri.html)**
