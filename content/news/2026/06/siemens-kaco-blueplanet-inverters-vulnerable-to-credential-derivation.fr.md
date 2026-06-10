---
title: "Les onduleurs Siemens KACO Blueplanet vulnérables à la dérivation d'identifiants"
date: "2026-06-10T10:51:15Z"
original_date: "2026-06-09T12:00:00"
lang: "fr"
translationKey: "siemens-kaco-blueplanet-inverters-vulnerable-to-credential-derivation"
author: "NewsBot (Validated by Federico Sella)"
description: "De multiples vulnérabilités dans les onduleurs KACO blueplanet permettent à des attaquants de dériver des identifiants à partir des numéros de série, obtenant ainsi un accès non autorisé. Siemens recommande des mises à jour."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02"
source: "CISA"
severity: "High"
target: "Onduleurs Siemens KACO Blueplanet"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

De multiples vulnérabilités dans les onduleurs KACO blueplanet permettent à des attaquants de dériver des identifiants à partir des numéros de série, obtenant ainsi un accès non autorisé. Siemens recommande des mises à jour.

{{< cyber-report severity="High" source="CISA" target="Onduleurs Siemens KACO Blueplanet" >}}

La CISA a publié un avis (ICSA-26-160-02) détaillant de multiples vulnérabilités dans les onduleurs Siemens KACO blueplanet. Ces failles pourraient permettre à un attaquant de dériver des identifiants à partir du numéro de série d'un appareil et de les utiliser pour obtenir un accès non autorisé à l'onduleur.

{{< ad-banner >}}

L'avis couvre une large gamme de modèles concernés, notamment blueplanet 100 NX3 M8, 100 TL3 GEN2, 105 TL3, et bien d'autres, avec des versions listées comme all/* ou des versions de firmware spécifiques inférieures à 6.1.4.9. KACO new energy GmbH a publié des mises à jour pour certains produits et prépare des correctifs pour d'autres, recommandant des contre-mesures là où les correctifs ne sont pas encore disponibles.

Aucun identifiant CVE ni score CVSS n'est fourni dans l'avis. Les vulnérabilités sont considérées comme sérieuses en raison du potentiel d'exploitation à distance menant à un accès non autorisé à l'appareil, ce qui pourrait impacter l'infrastructure d'énergie solaire.

{{< netrunner-insight >}}

Pour les analystes SOC et les ingénieurs DevSecOps, cet avis souligne le risque d'identifiants codés en dur ou dérivables dans les appareils IoT/OT. Inventoriez immédiatement les onduleurs KACO concernés et appliquez les mises à jour de firmware disponibles. Pour les unités non corrigées, mettez en œuvre une segmentation réseau et surveillez les tentatives d'accès anormales comme mesures d'atténuation provisoires.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02)**
