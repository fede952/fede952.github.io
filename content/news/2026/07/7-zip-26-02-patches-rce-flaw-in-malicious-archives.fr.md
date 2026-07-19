---
title: "7-Zip 26.02 corrige une faille d'exécution de code à distance dans les archives malveillantes"
date: "2026-07-19T09:02:18Z"
original_date: "2026-07-18T19:32:02"
lang: "fr"
translationKey: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
slug: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
author: "NewsBot (Validated by Federico Sella)"
description: "7-Zip a publié la version 26.02 pour corriger une vulnérabilité d'exécution de code à distance pouvant être déclenchée en ouvrant des fichiers compressés spécialement conçus. Mettez à jour immédiatement."
original_url: "https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/"
source: "BleepingComputer"
severity: "High"
target: "Utilisateurs de 7-Zip"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

7-Zip a publié la version 26.02 pour corriger une vulnérabilité d'exécution de code à distance pouvant être déclenchée en ouvrant des fichiers compressés spécialement conçus. Mettez à jour immédiatement.

{{< cyber-report severity="High" source="BleepingComputer" target="Utilisateurs de 7-Zip" >}}

La version 26.02 de 7-Zip a été publiée pour corriger une vulnérabilité d'exécution de code à distance (RCE) qui pourrait permettre à des attaquants d'exécuter du code arbitraire sur le système d'une victime. La faille est exploitable en convainquant les utilisateurs d'ouvrir des fichiers compressés spécialement conçus, comme des archives contenant des charges utiles malveillantes.

{{< ad-banner >}}

La vulnérabilité affecte toutes les versions antérieures du populaire archiveur de fichiers. Bien qu'aucun identifiant CVE n'ait été divulgué dans l'annonce, la sévérité est considérée comme élevée en raison du potentiel de compromission totale du système. Il est fortement recommandé aux utilisateurs de mettre à jour vers la dernière version immédiatement.

Compte tenu de l'utilisation généralisée de 7-Zip dans les environnements professionnels et grand public, ce correctif est essentiel pour réduire la surface d'attaque. Les organisations devraient prioriser le déploiement via des mécanismes de mise à jour automatisés ou une installation manuelle.

{{< netrunner-insight >}}

Les analystes SOC doivent surveiller toute activité inhabituelle liée aux fichiers d'archive et s'assurer que 7-Zip est mis à jour sur tous les points de terminaison. Les équipes DevSecOps doivent intégrer cette mise à jour dans leurs pipelines de gestion des correctifs et envisager de bloquer l'accès des versions plus anciennes de 7-Zip aux systèmes sensibles.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/)**
