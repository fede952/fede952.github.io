---
title: "CISA met en garde contre une faille de traversée de chemin dans ABB PCM600 menant à une exécution de code à distance"
date: "2026-05-01T08:59:15Z"
original_date: "2026-04-30T12:00:00"
lang: "fr"
translationKey: "cisa-warns-of-abb-pcm600-path-traversal-flaw-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "Les versions 1.5 à 2.13 d'ABB PCM600 sont vulnérables à une faille de traversée de chemin (CVE-2018-1002208) qui pourrait permettre l'exécution de code arbitraire. Mettez à jour vers la version 2.14."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02"
source: "CISA"
severity: "Medium"
target: "ABB PCM600"
cve: "CVE-2018-1002208"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Les versions 1.5 à 2.13 d'ABB PCM600 sont vulnérables à une faille de traversée de chemin (CVE-2018-1002208) qui pourrait permettre l'exécution de code arbitraire. Mettez à jour vers la version 2.14.

{{< cyber-report severity="Medium" source="CISA" target="ABB PCM600" cve="CVE-2018-1002208" >}}

CISA a publié un avis (ICSA-26-120-02) détaillant une vulnérabilité dans ABB PCM600, un gestionnaire d'IED de protection et de contrôle. La faille, identifiée sous le nom CVE-2018-1002208, existe dans la bibliothèque SharpZip.dll et implique une limitation incorrecte d'un chemin d'accès à un répertoire restreint (traversée de chemin). Une exploitation réussie pourrait permettre à un attaquant d'envoyer des messages spécialement conçus au nœud système, entraînant l'exécution de code arbitraire.

{{< ad-banner >}}

Les versions de produit concernées sont PCM600 de 1.5 jusqu'à 2.13 incluse. ABB a publié la version 2.14 pour remédier au problème. Cependant, notez que les relais de protection RE_630 ne sont pas compatibles avec PCM600 2.14, donc les utilisateurs de versions antérieures avec RE_630 doivent s'appuyer sur des défenses au niveau du système comme indiqué dans les recommandations générales de sécurité d'ABB.

L'avis souligne que le produit est déployé dans le monde entier dans le secteur de la fabrication critique. Bien qu'aucun score CVSS ne soit fourni dans l'avis, le potentiel d'exécution de code de la vulnérabilité justifie une correction rapide dans la mesure du possible. Les organisations devraient prioriser la mise à jour vers PCM600 2.14 et mettre en œuvre la segmentation du réseau et les contrôles d'accès pour les systèmes qui ne peuvent pas être mis à jour immédiatement.

{{< netrunner-insight >}}

Cette vulnérabilité de traversée de chemin dans ABB PCM600 rappelle que des dépendances héritées comme SharpZip.dll peuvent introduire des risques. Pour les analystes SOC, surveillez le trafic réseau anormal vers les nœuds PCM600, en particulier les messages conçus qui pourraient indiquer des tentatives d'exploitation. Les ingénieurs DevSecOps doivent inventorier toutes les instances de PCM600 et planifier les mises à niveau vers la version 2.14, tout en assurant la compatibilité avec les relais RE_630 via des contrôles compensatoires.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02)**
