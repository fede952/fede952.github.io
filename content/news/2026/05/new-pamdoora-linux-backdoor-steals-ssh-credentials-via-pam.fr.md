---
title: "Nouveau backdoor Linux PamDOORa vole des identifiants SSH via PAM"
date: "2026-05-09T08:29:08Z"
original_date: "2026-05-08T08:41:00"
lang: "fr"
translationKey: "new-pamdoora-linux-backdoor-steals-ssh-credentials-via-pam"
author: "NewsBot (Validated by Federico Sella)"
description: "Un nouveau backdoor Linux nommé PamDOORa, vendu sur un forum cybercriminel russe pour 1 600 $, utilise des modules PAM pour fournir un accès SSH persistant avec une combinaison de mot de passe magique et de port TCP."
original_url: "https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html"
source: "The Hacker News"
severity: "High"
target: "Serveurs SSH Linux"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un nouveau backdoor Linux nommé PamDOORa, vendu sur un forum cybercriminel russe pour 1 600 $, utilise des modules PAM pour fournir un accès SSH persistant avec une combinaison de mot de passe magique et de port TCP.

{{< cyber-report severity="High" source="The Hacker News" target="Serveurs SSH Linux" >}}

Des chercheurs en cybersécurité ont découvert un nouveau backdoor Linux appelé PamDOORa, annoncé sur le forum cybercriminel russe Rehub pour 1 600 $ par un acteur menaçant connu sous le nom de 'darkworm'. Le backdoor est conçu comme une boîte à outils post-exploitation basée sur un module d'authentification enfichable (PAM), permettant un accès SSH persistant via une combinaison d'un mot de passe magique et d'un port TCP spécifique.

{{< ad-banner >}}

PamDOORa fonctionne en interceptant l'authentification SSH via des modules PAM malveillants, permettant aux attaquants de contourner les identifiants normaux et d'obtenir un accès non autorisé. L'utilisation de modules PAM rend le backdoor furtif, car il s'intègre dans le flux d'authentification standard du système Linux.

La vente de tels outils sur les forums cybercriminels met en évidence la marchandisation continue des outils d'attaque sophistiqués. Il est conseillé aux organisations de surveiller les schémas d'authentification SSH inhabituels et de s'assurer que les configurations PAM sont auditées régulièrement.

{{< netrunner-insight >}}

Pour les analystes SOC, détecter PamDOORa nécessite de surveiller les connexions SSH inattendues sur des ports non standard et de les corréler avec les modifications des modules PAM. Les équipes DevSecOps doivent imposer une gestion stricte de la configuration PAM et envisager une surveillance de l'intégrité des fichiers pour /etc/pam.d/ et les bibliothèques associées. Ce backdoor souligne l'importance de considérer PAM comme une frontière de sécurité critique.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html)**
