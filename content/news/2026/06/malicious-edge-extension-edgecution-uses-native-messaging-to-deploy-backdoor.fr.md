---
title: "Extension malveillante Edge 'Edgecution' utilise la messagerie native pour déployer une porte dérobée"
date: "2026-06-25T10:16:09Z"
original_date: "2026-06-24T20:58:22"
lang: "fr"
translationKey: "malicious-edge-extension-edgecution-uses-native-messaging-to-deploy-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "Une extension malveillante de Microsoft Edge nommée 'Edgecution' s'échappe du bac à sable du navigateur via la messagerie native pour déployer une porte dérobée basée sur Python lors d'attaques de ransomware."
original_url: "https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/"
source: "BleepingComputer"
severity: "High"
target: "Utilisateurs de Microsoft Edge"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Une extension malveillante de Microsoft Edge nommée 'Edgecution' s'échappe du bac à sable du navigateur via la messagerie native pour déployer une porte dérobée basée sur Python lors d'attaques de ransomware.

{{< cyber-report severity="High" source="BleepingComputer" target="Utilisateurs de Microsoft Edge" >}}

Une extension malveillante de Microsoft Edge surnommée 'Edgecution' a été observée lors d'une attaque de ransomware, exploitant l'API de messagerie native du navigateur pour s'échapper du bac à sable et exécuter du code arbitraire sur le système hôte. L'extension agit comme un pont pour déployer une porte dérobée basée sur Python, permettant un accès persistant et d'autres activités malveillantes.

{{< ad-banner >}}

La chaîne d'attaque commence par l'installation de l'extension malveillante, qui abuse ensuite de la messagerie native pour communiquer avec une application native en dehors du bac à sable du navigateur. Cette technique contourne les limites de sécurité typiques du navigateur, permettant à l'attaquant d'exécuter des commandes et de déposer des charges utiles supplémentaires, y compris un ransomware.

Les chercheurs en sécurité soulignent que cette méthode est particulièrement insidieuse car elle exploite une fonctionnalité légitime du navigateur, rendant la détection difficile pour les solutions de sécurité traditionnelles des endpoints. Il est conseillé aux organisations de surveiller les extensions de navigateur non autorisées et de restreindre les autorisations de messagerie native lorsque cela est possible.

{{< netrunner-insight >}}

Cette attaque souligne l'importance de surveiller les installations d'extensions de navigateur et l'activité de messagerie native. Les analystes SOC doivent rechercher des comportements anormaux d'extensions et des communications hôtes natives inattendues, tandis que les équipes DevSecOps doivent appliquer des listes d'autorisation strictes d'extensions et désactiver les hôtes de messagerie native inutiles.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)**
