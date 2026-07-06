---
title: "Nouveau QuimaRAT basé sur Java, un MaaS ciblant Windows, Linux et macOS"
date: "2026-07-06T11:23:53Z"
original_date: "2026-07-06T08:13:33"
lang: "fr"
translationKey: "new-java-based-quimarat-maas-targets-windows-linux-macos"
slug: "new-java-based-quimarat-maas-targets-windows-linux-macos"
author: "NewsBot (Validated by Federico Sella)"
description: "QuimaRAT, un RAT Java multiplateforme vendu comme malware-as-a-service, menace les systèmes Windows, Linux et macOS. Les chercheurs de LevelBlue détaillent son modèle d'abonnement et ses capacités."
original_url: "https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html"
source: "The Hacker News"
severity: "High"
target: "systèmes Windows, Linux et macOS"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

QuimaRAT, un RAT Java multiplateforme vendu comme malware-as-a-service, menace les systèmes Windows, Linux et macOS. Les chercheurs de LevelBlue détaillent son modèle d'abonnement et ses capacités.

{{< cyber-report severity="High" source="The Hacker News" target="systèmes Windows, Linux et macOS" >}}

Les chercheurs en cybersécurité de LevelBlue ont identifié un nouveau cheval de Troie d'accès à distance (RAT) basé sur Java nommé QuimaRAT, capable de cibler les environnements Windows, Linux et macOS. Le malware est commercialisé selon un modèle de malware-as-a-service (MaaS), avec des niveaux d'abonnement allant de 150 $ pour un mois à 1 200 $ pour un accès à vie, ainsi qu'un niveau à 300 $.

{{< ad-banner >}}

La nature multiplateforme de QuimaRAT, rendue possible par Java, lui permet de compromettre divers systèmes d'exploitation, ce qui en fait une menace polyvalente pour les organisations disposant d'environnements hétérogènes. Le modèle MaaS abaisse la barrière à l'entrée pour les acteurs malveillants moins qualifiés, augmentant potentiellement la fréquence des attaques.

Bien que les détails techniques spécifiques sur les capacités de QuimaRAT soient limités dans le rapport initial, son architecture Java suggère qu'il pourrait exploiter des techniques courantes telles que l'enregistrement de frappe, la capture d'écran et l'exfiltration de fichiers. Les organisations doivent surveiller les processus Java suspects et mettre en œuvre une liste blanche d'applications pour atténuer le risque.

{{< netrunner-insight >}}

Pour les analystes SOC, la nature multiplateforme de QuimaRAT signifie que les règles de détection doivent couvrir les endpoints Windows, Linux et macOS. Les équipes DevSecOps doivent examiner l'utilisation de l'environnement d'exécution Java et envisager de restreindre l'exécution d'applications Java non signées. Compte tenu du modèle MaaS, attendez-vous à ce que des attaquants de faible sophistication déploient ce RAT, donc une surveillance de base des connexions réseau et des comportements de processus inhabituels est essentielle.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html)**
