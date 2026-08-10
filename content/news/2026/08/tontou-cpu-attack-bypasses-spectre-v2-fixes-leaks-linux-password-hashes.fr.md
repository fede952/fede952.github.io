---
title: "L'attaque CPU TONTOU contourne les correctifs de Spectre v2 et divulgue les hachages de mots de passe Linux"
date: "2026-08-10T08:26:15Z"
original_date: "2026-08-06T18:03:45"
lang: "fr"
translationKey: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
slug: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "Des chercheurs développent l'attaque TONTOU qui contourne les récentes atténuations de Spectre v2, parvenant à divulguer des secrets, y compris des hachages de mots de passe, depuis des systèmes Linux."
original_url: "https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/"
source: "BleepingComputer"
severity: "High"
target: "Systèmes Linux"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Des chercheurs développent l'attaque TONTOU qui contourne les récentes atténuations de Spectre v2, parvenant à divulguer des secrets, y compris des hachages de mots de passe, depuis des systèmes Linux.

{{< cyber-report severity="High" source="BleepingComputer" target="Systèmes Linux" >}}

Des chercheurs en sécurité ont dévoilé une nouvelle attaque par exécution spéculative, surnommée TONTOU, qui contourne les récentes atténuations de la vulnérabilité Spectre v2. L'attaque cible les mécanismes de prédiction de branche du CPU, qui avaient été corrigés pour empêcher les fuites par canal auxiliaire. En exploitant une faille dans ces défenses, les chercheurs ont réussi à extraire des données sensibles de la mémoire du noyau de machines Linux.

{{< ad-banner >}}

L'exploit de preuve de concept démontre la gravité du problème en divulguant avec succès des hachages de mots de passe du système cible. Cela indique que l'attaque pourrait être utilisée pour compromettre les identifiants des utilisateurs et potentiellement élever les privilèges. Ces résultats soulignent le défi permanent de l'atténuation complète des attaques par canal auxiliaire de l'exécution spéculative, car de nouvelles variantes continuent d'émerger malgré les correctifs précédents.

Bien que les chercheurs n'aient pas encore publié tous les détails techniques, leurs travaux soulignent la nécessité d'une vigilance continue en matière de sécurité des CPU. Les administrateurs système sont invités à surveiller les mises à jour des fournisseurs de CPU et des distributions Linux, et à envisager des mesures de durcissement supplémentaires telles que la randomisation de l'espace d'adressage du noyau (KASLR) et les mises à jour du microcode.

{{< netrunner-insight >}}

Cette attaque est un rappel frappant que les vulnérabilités d'exécution spéculative ne sont pas entièrement résolues. Les analystes SOC doivent prioriser les correctifs et surveiller tout indicateur d'exploitation, tandis que les ingénieurs DevSecOps doivent revoir leurs modèles de menace pour les risques de canal auxiliaire. Étant donné le potentiel de fuite de hachages de mots de passe, une attention immédiate aux mises à jour du noyau Linux et du microcode CPU est justifiée.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/)**
