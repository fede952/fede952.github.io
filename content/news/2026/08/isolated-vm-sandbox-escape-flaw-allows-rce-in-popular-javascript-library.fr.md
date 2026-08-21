---
title: "Faille d'évasion de sandbox dans isolated-vm permettant une exécution de code à distance dans une bibliothèque JavaScript populaire"
date: "2026-08-21T07:37:09Z"
original_date: "2026-08-20T13:48:24"
lang: "fr"
translationKey: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
slug: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
author: "NewsBot (Validated by Federico Sella)"
description: "Une faille critique dans isolated-vm permet à du code JavaScript sandboxé de s'échapper vers l'hôte, permettant potentiellement une exécution de code à distance. Toutes les versions jusqu'à 7.0.0 sont concernées."
original_url: "https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html"
source: "The Hacker News"
severity: "Critical"
target: "bibliothèque de sandbox JavaScript isolated-vm"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Une faille critique dans isolated-vm permet à du code JavaScript sandboxé de s'échapper vers l'hôte, permettant potentiellement une exécution de code à distance. Toutes les versions jusqu'à 7.0.0 sont concernées.

{{< cyber-report severity="Critical" source="The Hacker News" target="bibliothèque de sandbox JavaScript isolated-vm" >}}

Une vulnérabilité de sécurité critique a été divulguée dans isolated-vm, une bibliothèque de sandbox JavaScript open-source largement utilisée avec plus de 2 900 étoiles GitHub et 190 forks. La faille, suivie sous la référence GHSA-864f-rcv7-6rh4, permet aux attaquants de s'échapper de l'environnement sandbox et d'exécuter potentiellement du code arbitraire sur le système hôte. Toutes les versions de la bibliothèque jusqu'à la version 7.0.0 incluse sont concernées.

{{< ad-banner >}}

La vulnérabilité est particulièrement préoccupante car isolated-vm est conçu pour fournir une frontière sécurisée pour exécuter du code JavaScript non fiable. Une évasion de sandbox réussie pourrait compromettre l'application hôte et l'infrastructure sous-jacente. Bien qu'aucun identifiant CVE n'ait encore été attribué, l'avis de sécurité souligne la nécessité d'une attention immédiate de la part des développeurs utilisant cette bibliothèque.

Les organisations qui s'appuient sur isolated-vm doivent surveiller les correctifs et envisager des mesures de contrôle, telles que restreindre l'exécution de code non fiable ou appliquer des couches d'isolation supplémentaires. L'absence de CVE à ce stade ne diminue pas la gravité, car des preuves de concept d'exploitation pourraient déjà circuler dans la communauté de la sécurité.

{{< netrunner-insight >}}

Cette évasion de sandbox est un rappel frappant que même les outils d'isolation spécialement conçus peuvent avoir des failles critiques. Les analystes SOC doivent inventorier toutes les applications utilisant isolated-vm et prioriser le déploiement des correctifs dès qu'ils seront disponibles. Les équipes DevSecOps doivent également revoir leurs stratégies de sandboxing et envisager une défense en profondeur, comme l'exécution des sandbox dans des conteneurs ou des machines virtuelles séparés pour limiter le rayon d'explosion.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html)**
