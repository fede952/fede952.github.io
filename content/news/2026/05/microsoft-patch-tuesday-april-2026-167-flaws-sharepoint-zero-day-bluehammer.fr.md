---
title: "Patch Tuesday de Microsoft avril 2026 : 167 failles, zero-day SharePoint, BlueHammer"
date: "2026-05-11T10:37:48Z"
original_date: "2026-04-14T21:47:59"
lang: "fr"
translationKey: "microsoft-patch-tuesday-april-2026-167-flaws-sharepoint-zero-day-bluehammer"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft corrige 167 vulnérabilités, dont un zero-day SharePoint et une faille Windows Defender divulguée publiquement (BlueHammer). Google Chrome et Adobe Reader corrigent également des bugs activement exploités."
original_url: "https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/"
source: "Krebs on Security"
severity: "Critical"
target: "Microsoft Windows, SharePoint, Windows Defender, Chrome, Adobe Reader"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft corrige 167 vulnérabilités, dont un zero-day SharePoint et une faille Windows Defender divulguée publiquement (BlueHammer). Google Chrome et Adobe Reader corrigent également des bugs activement exploités.

{{< cyber-report severity="Critical" source="Krebs on Security" target="Microsoft Windows, SharePoint, Windows Defender, Chrome, Adobe Reader" >}}

Le Patch Tuesday d'avril 2026 de Microsoft corrige un nombre impressionnant de 167 vulnérabilités de sécurité dans Windows et les logiciels associés. Parmi les plus critiques figure une vulnérabilité zero-day dans SharePoint Server pouvant permettre l'exécution de code à distance, bien qu'aucun identifiant CVE n'ait été fourni dans le rapport. De plus, une faiblesse divulguée publiquement dans Windows Defender, surnommée 'BlueHammer', a été corrigée.

{{< ad-banner >}}

Par ailleurs, Google Chrome a corrigé son quatrième zero-day de 2026, poursuivant une tendance de mises à jour fréquentes du navigateur. Adobe Reader a également reçu une mise à jour d'urgence pour corriger une faille activement exploitée pouvant conduire à une exécution de code à distance. Les organisations devraient prioriser ces mises à jour compte tenu de l'exploitation active.

Le volume considérable de correctifs ce mois-ci souligne l'importance de processus de gestion des correctifs robustes. Les équipes de sécurité devraient se concentrer sur le zero-day SharePoint et le problème Windows Defender comme priorités immédiates, tout en s'assurant que Chrome et Adobe Reader sont mis à jour dans toute l'entreprise.

{{< netrunner-insight >}}

Pour les analystes SOC, priorisez le zero-day SharePoint et la faille BlueHammer de Windows Defender pour un correctif immédiat, car ils sont soit activement exploités, soit publiquement connus. Les équipes DevSecOps devraient intégrer ces mises à jour dans leurs pipelines CI/CD et vérifier que les outils de protection des terminaux ne sont pas perturbés par le correctif Defender. Les correctifs Chrome et Adobe Reader méritent également une attention urgente compte tenu de leur statut d'exploitation active.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur Krebs on Security ›](https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/)**
