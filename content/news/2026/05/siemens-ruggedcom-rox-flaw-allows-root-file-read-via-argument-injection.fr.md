---
title: "Vulnérabilité dans Siemens Ruggedcom ROX permettant la lecture de fichiers root par injection d'arguments"
date: "2026-05-17T09:01:07Z"
original_date: "2026-05-14T12:00:00"
lang: "fr"
translationKey: "siemens-ruggedcom-rox-flaw-allows-root-file-read-via-argument-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerte sur CVE-2025-40948 affectant plusieurs appareils Ruggedcom ROX. Un attaquant distant authentifié peut lire des fichiers arbitraires avec les privilèges root. Mettez à jour vers la version 2.17.1 ou ultérieure."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02"
source: "CISA"
severity: "Medium"
target: "Appareils Siemens Ruggedcom ROX"
cve: "CVE-2025-40948"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerte sur CVE-2025-40948 affectant plusieurs appareils Ruggedcom ROX. Un attaquant distant authentifié peut lire des fichiers arbitraires avec les privilèges root. Mettez à jour vers la version 2.17.1 ou ultérieure.

{{< cyber-report severity="Medium" source="CISA" target="Appareils Siemens Ruggedcom ROX" cve="CVE-2025-40948" cvss="6.8" >}}

Les appareils de la série Siemens Ruggedcom ROX sont affectés par une vulnérabilité de contrôle d'accès inapproprié (CVE-2025-40948) qui permet à un attaquant distant authentifié de lire des fichiers arbitraires avec les privilèges root du système d'exploitation sous-jacent. Le défaut provient d'une validation incorrecte des entrées dans l'interface JSON-RPC du serveur web, permettant une injection d'arguments.

{{< ad-banner >}}

Les produits suivants sont vulnérables : RUGGEDCOM ROX MX5000, MX5000RE, RX1400, RX1500, RX1501, RX1510, RX1511, RX1512, RX1524, RX1536 et RX5000, tous avec des versions antérieures à 2.17.1. Siemens a publié des mises à jour pour corriger le problème et recommande une application immédiate des correctifs.

Avec un score CVSS v3 de 6,8, cette vulnérabilité est classée de sévérité Moyenne. Le vecteur d'attaque est réseau, nécessite des privilèges faibles et aucune interaction utilisateur. Compte tenu des secteurs d'infrastructures critiques (par exemple, la fabrication critique) où ces appareils sont déployés, l'exploitation pourrait entraîner une divulgation significative d'informations.

{{< netrunner-insight >}}

Pour les analystes SOC : priorisez le correctif des appareils Ruggedcom ROX dans votre environnement, en particulier ceux exposés à des réseaux non fiables. La nature authentifiée de l'exploit réduit le risque immédiat mais ne l'élimine pas — les attaquants qui compromettent un compte à faibles privilèges peuvent escalader vers un accès complet aux fichiers root. Les équipes DevSecOps doivent examiner le durcissement des points de terminaison JSON-RPC et envisager une segmentation réseau pour limiter l'exposition.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02)**
