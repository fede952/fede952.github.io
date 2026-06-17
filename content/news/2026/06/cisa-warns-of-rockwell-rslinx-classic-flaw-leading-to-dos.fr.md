---
title: "CISA met en garde contre une faille Rockwell RSLinx Classic menant à un déni de service"
date: "2026-06-17T11:42:55Z"
original_date: "2026-06-16T12:00:00"
lang: "fr"
translationKey: "cisa-warns-of-rockwell-rslinx-classic-flaw-leading-to-dos"
author: "NewsBot (Validated by Federico Sella)"
description: "L'avis de CISA met en lumière CVE-2020-13573, un débordement de tampon basé sur la pile dans Rockwell Automation RSLinx Classic ≤4.50.00, risquant un déni de service et une exécution de code à distance."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02"
source: "CISA"
severity: "High"
target: "Rockwell Automation RSLinx Classic"
cve: "CVE-2020-13573"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

L'avis de CISA met en lumière CVE-2020-13573, un débordement de tampon basé sur la pile dans Rockwell Automation RSLinx Classic ≤4.50.00, risquant un déni de service et une exécution de code à distance.

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation RSLinx Classic" cve="CVE-2020-13573" cvss="7.5" >}}

CISA a publié un avis (ICSA-26-167-02) concernant une vulnérabilité dans Rockwell Automation RSLinx Classic, un logiciel de communication industrielle largement utilisé. La faille, identifiée comme CVE-2020-13573, est un débordement de tampon basé sur la pile qui peut être exploité à distance pour exécuter du code arbitraire ou provoquer un déni de service, rendant l'application non réactive et incapable de récupérer automatiquement.

{{< ad-banner >}}

Les versions concernées incluent RSLinx Classic jusqu'à la version 4.50.00 incluse. La vulnérabilité a un score CVSS v3 de 7,5, indiquant une sévérité élevée. Rockwell Automation recommande de passer à la version 4.60.00 ou ultérieure, ou d'appliquer le correctif BF31213 pour les clients qui ne peuvent pas mettre à jour immédiatement. L'avis mentionne également CWE-125 (Lecture hors limites) comme faiblesse sous-jacente.

Compte tenu des secteurs d'infrastructures critiques concernés—Fabrication critique, Énergie, Alimentation et agriculture, et Eau et eaux usées—ainsi que du déploiement mondial du produit, une mise à jour rapide est essentielle. Les organisations devraient prioriser cette mise à jour pour atténuer le risque d'exploitation, en particulier dans les environnements où RSLinx Classic est exposé à des réseaux non fiables.

{{< netrunner-insight >}}

Pour les analystes SOC, surveillez les plantages inhabituels ou l'absence de réponse des processus RSLinx Classic, car cela peut indiquer des tentatives d'exploitation. Les équipes DevSecOps doivent immédiatement planifier la mise à niveau vers la version 4.60.00 ou appliquer le correctif BF31213, et s'assurer que les instances RSLinx ne sont pas directement accessibles depuis Internet. Compte tenu du score CVSS et du potentiel d'exécution de code à distance, traitez cela comme un élément de correction hautement prioritaire.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02)**
