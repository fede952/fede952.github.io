---
title: "Preuve de concept de contournement zero-day de BitLocker Windows publiée : YellowKey et GreenPlasma"
date: "2026-05-14T09:30:15Z"
original_date: "2026-05-13T16:37:49"
lang: "fr"
translationKey: "windows-bitlocker-zero-day-bypass-poc-released-yellowkey-and-greenplasma"
author: "NewsBot (Validated by Federico Sella)"
description: "Des preuves de concept pour deux vulnérabilités Windows non corrigées—YellowKey (contournement de BitLocker) et GreenPlasma (élévation de privilèges)—ont été publiées, posant des risques pour les disques chiffrés."
original_url: "https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/"
source: "BleepingComputer"
severity: "High"
target: "Disques protégés par BitLocker Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Des preuves de concept pour deux vulnérabilités Windows non corrigées—YellowKey (contournement de BitLocker) et GreenPlasma (élévation de privilèges)—ont été publiées, posant des risques pour les disques chiffrés.

{{< cyber-report severity="High" source="BleepingComputer" target="Disques protégés par BitLocker Windows" >}}

Un chercheur en cybersécurité a publié des preuves de concept (PoC) pour deux vulnérabilités Microsoft Windows non corrigées, surnommées YellowKey et GreenPlasma. YellowKey est un contournement de BitLocker qui permet aux attaquants d'accéder aux données sur des disques protégés sans authentification appropriée, tandis que GreenPlasma est une faille d'élévation de privilèges qui pourrait permettre à un attaquant d'obtenir des permissions élevées sur un système compromis.

{{< ad-banner >}}

La publication de ces PoC augmente le risque d'exploitation, car les acteurs malveillants peuvent désormais utiliser ces techniques. Les organisations qui utilisent BitLocker pour le chiffrement complet du disque doivent évaluer leur exposition et envisager des contrôles de sécurité supplémentaires, comme l'activation de la protection TPM+PIN ou l'utilisation d'une authentification avant démarrage.

Microsoft n'a pas encore publié de correctifs pour ces vulnérabilités, laissant les systèmes exposés jusqu'à ce que les correctifs soient déployés. Les équipes de sécurité doivent surveiller les schémas d'accès inhabituels aux disques chiffrés et appliquer des solutions de contournement lorsque cela est possible, comme la désactivation des options de démarrage inutiles ou l'application de politiques de code PIN strictes.

{{< netrunner-insight >}}

Pour les analystes SOC, priorisez la surveillance des tentatives non autorisées d'accès aux disques protégés par BitLocker et des événements d'élévation de privilèges. Les ingénieurs DevSecOps doivent tester leurs environnements par rapport aux PoC publiés pour identifier les configurations vulnérables et mettre en œuvre des contrôles compensatoires comme Secure Boot et les journaux de démarrage mesurés.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)**
