---
title: "PamStealer : un voleur macOS utilise de faux sites Maccy et des vérifications PAM"
date: "2026-07-04T09:17:53Z"
original_date: "2026-07-03T08:03:37"
lang: "fr"
translationKey: "pamstealer-macos-stealer-uses-fake-maccy-sites-and-pam-checks"
author: "NewsBot (Validated by Federico Sella)"
description: "Jamf Threat Labs découvre PamStealer, un voleur d'informations macOS distribué via de faux sites Maccy, qui utilise des vérifications PAM pour voler les mots de passe de connexion."
original_url: "https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html"
source: "The Hacker News"
severity: "High"
target: "utilisateurs macOS"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Jamf Threat Labs découvre PamStealer, un voleur d'informations macOS distribué via de faux sites Maccy, qui utilise des vérifications PAM pour voler les mots de passe de connexion.

{{< cyber-report severity="High" source="The Hacker News" target="utilisateurs macOS" >}}

Des chercheurs en cybersécurité de Jamf Threat Labs ont identifié un nouveau voleur d'informations macOS nommé PamStealer. Le logiciel malveillant est distribué sous la forme d'un fichier AppleScript compilé (.scpt) qui se fait passer pour Maccy, un gestionnaire de presse-papiers open source légitime. Il utilise une série d'astuces ingénieuses pour infecter les systèmes et siphonner des données sensibles, y compris les mots de passe de connexion.

{{< ad-banner >}}

PamStealer tire son nom de sa capacité à abuser du framework Pluggable Authentication Module (PAM) sur macOS. En interceptant les processus d'authentification, il peut capturer les identifiants des utilisateurs lorsqu'ils se connectent ou s'authentifient pour des opérations privilégiées. Le voleur exfiltre ensuite les données volées vers des serveurs contrôlés par les attaquants.

La campagne repose sur de faux sites web et de l'ingénierie sociale pour inciter les utilisateurs à télécharger le fichier .scpt malveillant. Une fois exécuté, le logiciel malveillant effectue des vérifications PAM pour récolter les mots de passe sans éveiller les soupçons. Les organisations disposant de terminaux macOS doivent surveiller les exécutions inhabituelles de fichiers .scpt et les anomalies liées à PAM.

{{< netrunner-insight >}}

Pour les analystes SOC, cela souligne la nécessité de surveiller les exécutions d'AppleScript compilé et les modifications de PAM sur les terminaux macOS. Les équipes DevSecOps doivent appliquer une liste blanche d'applications et éduquer les utilisateurs sur la vérification des sources logicielles, en particulier pour les gestionnaires de presse-papiers. La mise en œuvre de règles de détection des points de terminaison pour les abus de PAM peut aider à détecter ce voleur à un stade précoce.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html)**
