---
title: "MITRE ATT&CK v19 remanie la défense anti-contournement avec de nouvelles tactiques"
date: "2026-06-23T10:34:05Z"
original_date: "2026-06-23T10:14:50"
lang: "fr"
translationKey: "mitre-att-ck-v19-overhauls-defense-evasion-with-new-tactics"
author: "NewsBot (Validated by Federico Sella)"
description: "MITRE ATT&CK v19 introduit des changements structurels, dépréciant la défense anti-contournement (TA0005) et ajoutant Stealthee et Impair Defenses. Un guide de migration est fourni."
original_url: "https://www.cybersecurity360.it/nuove-minacce/mitre-attck-v19-ecco-le-novita-strutturali-della-nuova-versione/"
source: "Cybersecurity360"
severity: "Info"
target: "Utilisateurs du framework MITRE ATT&CK"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

MITRE ATT&CK v19 introduit des changements structurels, dépréciant la défense anti-contournement (TA0005) et ajoutant Stealthee et Impair Defenses. Un guide de migration est fourni.

{{< cyber-report severity="Info" source="Cybersecurity360" target="Utilisateurs du framework MITRE ATT&CK" >}}

MITRE a publié la version 19 du framework ATT&CK, introduisant des modifications structurelles importantes. Le changement le plus notable est la dépréciation de la tactique de défense anti-contournement (TA0005), remplacée par deux nouvelles tactiques : Stealthee et Impair Defenses. Cette restructuration vise à offrir une catégorisation plus granulaire des comportements adverses liés à l'évitement de la détection et à la perturbation des défenses.

{{< ad-banner >}}

La mise à jour inclut un guide de migration pour aider les organisations à transitionner leurs modèles de menace et leurs règles de détection de l'ancienne tactique vers les nouvelles. Les praticiens sont invités à revoir leurs correspondances actuelles avec la défense anti-contournement et à réaffecter les techniques aux nouvelles tactiques appropriées pour maintenir la couverture.

Bien qu'aucun CVE ou vulnérabilité spécifique ne soit associé à cette version, la mise à jour du framework a des implications pour les opérations SOC et la chasse aux menaces. Les équipes doivent mettre à jour leurs références MITRE ATT&CK et ajuster les analyses qui reposent sur l'ID de tactique dépréciée.

{{< netrunner-insight >}}

Pour les analystes SOC, cela signifie mettre à jour vos règles de détection et vos requêtes de chasse aux menaces qui référencent TA0005. Les ingénieurs DevSecOps doivent examiner les correspondances de sécurité des pipelines CI/CD pour s'assurer qu'elles s'alignent sur les nouvelles tactiques. Le guide de migration est essentiel pour éviter les lacunes de couverture pendant la transition.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur Cybersecurity360 ›](https://www.cybersecurity360.it/nuove-minacce/mitre-attck-v19-ecco-le-novita-strutturali-della-nuova-versione/)**
