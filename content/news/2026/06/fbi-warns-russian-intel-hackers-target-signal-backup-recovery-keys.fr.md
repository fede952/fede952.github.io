---
title: "Le FBI met en garde contre des pirates du renseignement russe ciblant les clés de récupération de sauvegarde Signal"
date: "2026-06-28T09:57:31Z"
original_date: "2026-06-26T19:38:29"
lang: "fr"
translationKey: "fbi-warns-russian-intel-hackers-target-signal-backup-recovery-keys"
author: "NewsBot (Validated by Federico Sella)"
description: "Mise à jour de l'avertissement du FBI et de la CISA : le phishing du renseignement russe vole désormais les clés de récupération de sauvegarde Signal pour lire les messages privés et prendre le contrôle des comptes."
original_url: "https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html"
source: "The Hacker News"
severity: "High"
target: "Utilisateurs de Signal"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Mise à jour de l'avertissement du FBI et de la CISA : le phishing du renseignement russe vole désormais les clés de récupération de sauvegarde Signal pour lire les messages privés et prendre le contrôle des comptes.

{{< cyber-report severity="High" source="The Hacker News" target="Utilisateurs de Signal" >}}

Le FBI et la CISA ont mis à jour leur avertissement de mars concernant les campagnes de phishing du renseignement russe ciblant les comptes Signal. Les attaquants ont ajouté une nouvelle étape : ils incitent désormais leurs cibles à fournir leur clé de récupération de sauvegarde Signal. Une fois obtenue, la clé permet à l'attaquant de restaurer la sauvegarde du compte, de lire l'historique des messages privés et de groupe, et de prendre entièrement le contrôle du compte.

{{< ad-banner >}}

La clé reste valide même après la compromission initiale, permettant un accès persistant. Cette technique contourne l'authentification à deux facteurs traditionnelle car la clé de récupération est conçue pour la restauration légitime du compte. L'avis souligne que les utilisateurs ne doivent jamais partager leur clé de récupération et doivent activer le verrouillage d'enregistrement et d'autres fonctionnalités de sécurité.

Les organisations devraient sensibiliser les utilisateurs à ce vecteur de phishing spécifique et envisager de mettre en œuvre des étapes de vérification supplémentaires pour les communications sensibles. La menace est attribuée aux acteurs du renseignement russe, soulignant le contexte géopolitique de la campagne.

{{< netrunner-insight >}}

C'est un exemple typique d'ingénierie sociale ciblant une fonctionnalité de sécurité. Les analystes SOC doivent surveiller les demandes de récupération de compte inhabituelles et informer les utilisateurs que la clé de récupération de sauvegarde Signal ne doit jamais être partagée. Les équipes DevSecOps devraient envisager d'intégrer une authentification résistante au phishing pour les communications critiques.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html)**
