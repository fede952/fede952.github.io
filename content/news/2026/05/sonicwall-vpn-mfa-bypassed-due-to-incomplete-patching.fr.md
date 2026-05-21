---
title: "Contournement de l'authentification multifacteur SonicWall VPN en raison d'un correctif incomplet"
date: "2026-05-21T10:35:14Z"
original_date: "2026-05-20T21:19:17"
lang: "fr"
translationKey: "sonicwall-vpn-mfa-bypassed-due-to-incomplete-patching"
author: "NewsBot (Validated by Federico Sella)"
description: "Des acteurs malveillants forcent les identifiants VPN par brute-force et contournent l'authentification multifacteur sur des appliances SonicWall Gen6 SSL-VPN non corrigées, déployant des outils de ransomware."
original_url: "https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/"
source: "BleepingComputer"
severity: "High"
target: "Appareils SonicWall Gen6 SSL-VPN"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Des acteurs malveillants forcent les identifiants VPN par brute-force et contournent l'authentification multifacteur sur des appliances SonicWall Gen6 SSL-VPN non corrigées, déployant des outils de ransomware.

{{< cyber-report severity="High" source="BleepingComputer" target="Appareils SonicWall Gen6 SSL-VPN" >}}

Des acteurs malveillants ont été observés en train de forcer les identifiants VPN par brute-force et de contourner l'authentification multifacteur (MFA) sur des appliances SonicWall Gen6 SSL-VPN. Les attaques exploitent un correctif incomplet, permettant aux adversaires de déployer des outils couramment utilisés dans les opérations de ransomware.

{{< ad-banner >}}

La vulnérabilité permet aux attaquants d'obtenir un accès non autorisé aux réseaux internes après avoir compromis les identifiants VPN. Une fois à l'intérieur, ils peuvent se déplacer latéralement et déployer des charges utiles de ransomware, posant un risque significatif pour les organisations qui dépendent de ces appliances pour l'accès à distance.

SonicWall a publié des correctifs pour résoudre le problème, mais l'application incomplète de ces mises à jour laisse les systèmes exposés. Les organisations sont invitées à vérifier que tous les correctifs recommandés sont entièrement installés et à surveiller les signes d'accès VPN non autorisé.

{{< netrunner-insight >}}

Cet incident souligne l'importance cruciale d'une gestion rigoureuse des correctifs. Les analystes SOC devraient prioriser la vérification que toutes les appliances SonicWall Gen6 disposent du dernier firmware et surveiller les logs VPN pour des schémas d'authentification anormaux. Les équipes DevSecOps devraient envisager de mettre en œuvre des couches supplémentaires d'authentification multifacteur et une segmentation réseau pour atténuer ces contournements.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/)**
