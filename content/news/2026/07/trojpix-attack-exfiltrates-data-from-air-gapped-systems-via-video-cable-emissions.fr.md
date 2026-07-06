---
title: "L'attaque TrojPix exfiltre des données de systèmes isolés via les émissions des câbles vidéo"
date: "2026-07-06T11:24:53Z"
original_date: "2026-07-06T08:50:54"
lang: "fr"
translationKey: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
slug: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
author: "NewsBot (Validated by Federico Sella)"
description: "Des chercheurs démontrent TrojPix, une technique qui fuit des données d'ordinateurs isolés en modulant les pixels à l'écran pour émettre de faibles signaux radio depuis les câbles vidéo, nécessitant un accès préalable par malware."
original_url: "https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html"
source: "The Hacker News"
severity: "Medium"
target: "Systèmes isolés"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Des chercheurs démontrent TrojPix, une technique qui fuit des données d'ordinateurs isolés en modulant les pixels à l'écran pour émettre de faibles signaux radio depuis les câbles vidéo, nécessitant un accès préalable par malware.

{{< cyber-report severity="Medium" source="The Hacker News" target="Systèmes isolés" >}}

Des chercheurs de l'Université de Shandong ont dévoilé TrojPix, une attaque inédite qui exfiltre des données d'ordinateurs isolés en exploitant les émissions électromagnétiques des câbles vidéo. La technique modifie subtilement les pixels à l'écran d'une manière imperceptible à l'œil humain, ce qui amène le câble vidéo à rayonner un faible signal radio pouvant être capté et décodé par un récepteur proche.

{{< ad-banner >}}

TrojPix nécessite l'installation préalable d'un malware sur le système cible pour manipuler les valeurs des pixels. Cette approche atteint des débits de transfert de données nettement plus élevés que les canaux cachés précédents pour systèmes isolés, ce qui en fait une menace pratique pour les environnements hautement sécurisés. L'attaque souligne le défi permanent de protéger les données même dans des réseaux physiquement isolés.

Bien que la technique soit sophistiquée, sa dépendance à un malware préexistant limite son applicabilité. Les organisations devraient se concentrer sur la prévention de la compromission initiale grâce à une sécurité robuste des terminaux et à la surveillance des émissions électromagnétiques inhabituelles dans les zones sensibles.

{{< netrunner-insight >}}

Pour les analystes SOC, TrojPix souligne que les systèmes isolés ne sont pas à l'abri de l'exfiltration de données. Surveillez les signaux électromagnétiques anormaux près des postes de travail sensibles et appliquez une sécurité physique stricte. Les équipes DevSecOps devraient envisager de blinder les câbles vidéo et de mettre en œuvre une détection d'anomalies au niveau des pixels lorsque cela est possible.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html)**
