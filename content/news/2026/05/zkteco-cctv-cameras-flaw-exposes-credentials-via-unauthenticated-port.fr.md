---
title: "Les caméras CCTV ZKTeco exposent des identifiants via un port non authentifié"
date: "2026-05-20T10:24:09Z"
original_date: "2026-05-19T12:00:00"
lang: "fr"
translationKey: "zkteco-cctv-cameras-flaw-exposes-credentials-via-unauthenticated-port"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA met en garde contre CVE-2026-8598 dans les caméras CCTV ZKTeco, permettant le vol d'identifiants via un port non documenté. Correctif disponible dans le firmware V5.0.1.2.20260421."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04"
source: "CISA"
severity: "Critical"
target: "Caméras CCTV ZKTeco"
cve: "CVE-2026-8598"
cvss: 9.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA met en garde contre CVE-2026-8598 dans les caméras CCTV ZKTeco, permettant le vol d'identifiants via un port non documenté. Correctif disponible dans le firmware V5.0.1.2.20260421.

{{< cyber-report severity="Critical" source="CISA" target="Caméras CCTV ZKTeco" cve="CVE-2026-8598" cvss="9.1" >}}

CISA a publié un avis (ICSA-26-139-04) détaillant une vulnérabilité critique de contournement d'authentification dans les caméras CCTV ZKTeco. La faille, suivie sous le nom CVE-2026-8598, implique un port d'exportation de configuration non documenté accessible sans authentification. Une exploitation réussie pourrait entraîner une divulgation d'informations, y compris la capture des identifiants du compte de la caméra.

{{< ad-banner >}}

La vulnérabilité affecte les versions de firmware ZKTeco SSC335-GC2063-Face-0b77 Solution antérieures à V5.0.1.2.20260421. Le score de base CVSS v3 est de 9,1, indiquant une sévérité critique. Les appareils concernés sont déployés dans le monde entier dans des installations commerciales, le fournisseur étant basé en Chine.

ZKTeco a publié une version corrigée du firmware V5.0.1.2.20260421 pour résoudre le problème. Les utilisateurs sont fortement invités à mettre à jour immédiatement. La vulnérabilité est classée sous CWE-288 (contournement d'authentification via un chemin ou canal alternatif).

{{< netrunner-insight >}}

C'est un exemple typique d'une interface de débogage exposée devenant une porte dérobée. Les analystes SOC doivent immédiatement scanner les caméras ZKTeco sur leur réseau et vérifier les versions de firmware. Pour les DevSecOps, cela souligne la nécessité de désactiver ou de bloquer par pare-feu les ports non documentés dans les builds de firmware IoT. Considérez toute caméra avec un firmware inférieur à V5.0.1.2.20260421 comme compromise jusqu'à preuve du contraire.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04)**
