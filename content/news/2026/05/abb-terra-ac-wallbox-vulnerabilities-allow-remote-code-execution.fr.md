---
title: "Vulnérabilités de la borne ABB Terra AC Wallbox permettant l'exécution de code à distance"
date: "2026-05-22T10:24:17Z"
original_date: "2026-05-21T12:00:00"
lang: "fr"
translationKey: "abb-terra-ac-wallbox-vulnerabilities-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA met en garde contre des débordements de tas et de pile dans ABB Terra AC Wallbox (JP) ≤1.8.33 ; mettre à jour vers 1.8.36 pour atténuer CVE-2025-10504, CVE-2025-12142, CVE-2025-12143."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05"
source: "CISA"
severity: "Medium"
target: "ABB Terra AC Wallbox (JP)"
cve: "CVE-2025-10504"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA met en garde contre des débordements de tas et de pile dans ABB Terra AC Wallbox (JP) ≤1.8.33 ; mettre à jour vers 1.8.36 pour atténuer CVE-2025-10504, CVE-2025-12142, CVE-2025-12143.

{{< cyber-report severity="Medium" source="CISA" target="ABB Terra AC Wallbox (JP)" cve="CVE-2025-10504" cvss="6.1" >}}

ABB a divulgué plusieurs vulnérabilités affectant sa gamme de produits Terra AC Wallbox (JP), en particulier les versions jusqu'à 1.8.33 incluse. Les failles incluent un débordement de tas (CVE-2025-10504), une copie de tampon sans vérification de la taille d'entrée (CVE-2025-12142) et un débordement de pile (CVE-2025-12143). Une exploitation réussie pourrait permettre à un attaquant de corrompre la mémoire tas, conduisant potentiellement au contrôle à distance de l'appareil et à des écritures non autorisées dans la mémoire flash, modifiant ainsi le comportement du firmware.

{{< ad-banner >}}

Les vulnérabilités sont notées avec un score de base CVSS v3 de 6,1, indiquant une sévérité moyenne. ABB a publié la version 1.8.36 du firmware pour résoudre ces problèmes. Les produits sont déployés dans le monde entier dans le secteur de l'énergie, et le fournisseur recommande d'appliquer la mise à jour dès que possible.

Bien qu'aucune exploitation active n'ait été signalée, le potentiel d'exécution de code à distance et de manipulation du firmware rend ces vulnérabilités critiques pour les opérateurs d'infrastructures de recharge pour véhicules électriques. Les organisations devraient prioriser le correctif des appareils concernés, en particulier ceux exposés à des réseaux non fiables.

{{< netrunner-insight >}}

Pour les analystes SOC, surveillez le trafic anormal vers les appareils Terra AC Wallbox, en particulier les opérations d'écriture inattendues dans la mémoire flash. Les ingénieurs DevSecOps doivent imposer une validation stricte des entrées dans tout protocole personnalisé communiquant avec le chargeur et s'assurer que les mises à jour du firmware sont appliquées rapidement. Compte tenu du score CVSS de 6,1, traitez-les comme une priorité moyenne mais avec un impact potentiel élevé en raison du rôle de l'appareil dans l'infrastructure énergétique critique.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05)**
