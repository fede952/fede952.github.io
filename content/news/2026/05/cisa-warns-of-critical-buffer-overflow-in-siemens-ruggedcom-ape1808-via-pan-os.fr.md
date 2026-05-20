---
title: "CISA met en garde contre un débordement de tampon critique dans Siemens RUGGEDCOM APE1808 via PAN-OS"
date: "2026-05-20T10:21:56Z"
original_date: "2026-05-19T12:00:00"
lang: "fr"
translationKey: "cisa-warns-of-critical-buffer-overflow-in-siemens-ruggedcom-ape1808-via-pan-os"
author: "NewsBot (Validated by Federico Sella)"
description: "Un débordement de tampon dans le portail captif PAN-OS de Palo Alto Networks affecte les appareils Siemens RUGGEDCOM APE1808. CVE-2026-0300 permet l'exécution de code à distance non authentifiée avec les privilèges root."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02"
source: "CISA"
severity: "Critical"
target: "Appareils Siemens RUGGEDCOM APE1808"
cve: "CVE-2026-0300"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un débordement de tampon dans le portail captif PAN-OS de Palo Alto Networks affecte les appareils Siemens RUGGEDCOM APE1808. CVE-2026-0300 permet l'exécution de code à distance non authentifiée avec les privilèges root.

{{< cyber-report severity="Critical" source="CISA" target="Appareils Siemens RUGGEDCOM APE1808" cve="CVE-2026-0300" cvss="10.0" >}}

CISA a publié un avis (ICSA-26-139-02) détaillant une vulnérabilité critique de débordement de tampon dans le service User-ID Authentication Portal (portail captif) du logiciel PAN-OS de Palo Alto Networks. Cette faille, suivie sous CVE-2026-0300 avec un score CVSS de 10,0, permet à un attaquant non authentifié d'exécuter du code arbitraire avec les privilèges root sur les pare-feu des séries PA et VM en envoyant des paquets spécialement conçus.

{{< ad-banner >}}

La vulnérabilité affecte les appareils Siemens RUGGEDCOM APE1808 dans toutes les versions. Siemens prépare des versions correctives et recommande de mettre en œuvre les solutions de contournement fournies dans les notifications de sécurité en amont de Palo Alto Networks. En attendant les correctifs, les organisations devraient désactiver le service de portail captif s'il n'est pas nécessaire et restreindre l'accès réseau aux appareils concernés.

Compte tenu du score CVSS critique et du potentiel de compromission totale du système, une action immédiate est justifiée. L'avis cible le secteur de la fabrication critique, avec des appareils déployés dans le monde entier. Les opérateurs devraient prioriser l'application des mesures d'atténuation et surveiller tout signe d'exploitation.

{{< netrunner-insight >}}

C'est un exemple typique de risque lié à la chaîne d'approvisionnement : un composant tiers (PAN-OS) introduit une faille critique dans un produit industriel. Les analystes SOC doivent immédiatement rechercher un trafic anormal vers les ports du portail captif et s'assurer que la segmentation limite l'exposition. Les équipes DevSecOps doivent inventorier toutes les instances de RUGGEDCOM APE1808 et appliquer sans délai les mesures d'atténuation en amont de Palo Alto Networks.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02)**
