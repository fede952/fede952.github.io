---
title: "Le botnet NadMesh cible les services d'IA exposés pour voler des identifiants cloud"
date: "2026-07-19T09:05:56Z"
original_date: "2026-07-17T17:12:23"
lang: "fr"
translationKey: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
slug: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "Un nouveau botnet basé sur Go, NadMesh, traque les plateformes d'IA exposées comme ComfyUI et Ollama, dérobant des clés AWS et des tokens Kubernetes. Plus de 3 800 clés auraient été volées."
original_url: "https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html"
source: "The Hacker News"
severity: "High"
target: "Services d'IA exposés (ComfyUI, Ollama, n8n, etc.)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un nouveau botnet basé sur Go, NadMesh, traque les plateformes d'IA exposées comme ComfyUI et Ollama, dérobant des clés AWS et des tokens Kubernetes. Plus de 3 800 clés auraient été volées.

{{< cyber-report severity="High" source="The Hacker News" target="Services d'IA exposés (ComfyUI, Ollama, n8n, etc.)" >}}

Un nouveau botnet nommé NadMesh, écrit en Go, a émergé début juillet 2026, ciblant les services d'IA exposés pour voler des identifiants cloud et des tokens Kubernetes. Le tableau de bord de l'opérateur du botnet montrerait 3 811 clés AWS uniques récoltées, indiquant une échelle opérationnelle significative. NadMesh utilise un moissonneur basé sur Shodan pour alimenter en continu sa file d'attente de scan avec des instances vulnérables d'outils d'IA populaires tels que ComfyUI, Ollama, n8n, Open WebUI, Langflow et Gradio.

{{< ad-banner >}}

Ces plateformes d'IA sont souvent déployées rapidement par les équipes de développement sans durcissement de sécurité approprié, les laissant exposées à Internet. Le botnet exploite ce manque de protection pare-feu pour y accéder et extraire des identifiants sensibles. L'accent mis sur les services d'IA suggère un changement dans le ciblage des attaquants vers des infrastructures cloud de grande valeur et des pipelines d'apprentissage automatique.

Les organisations utilisant ces outils d'IA doivent immédiatement auditer leur exposition, restreindre l'accès réseau et renouveler tout identifiant qui pourrait avoir été compromis. Le botnet NadMesh démontre le paysage de menaces croissant où les services d'IA mal configurés deviennent des cibles de choix pour le vol d'identifiants et le mouvement latéral.

{{< netrunner-insight >}}

Pour les analystes SOC : priorisez la recherche de ComfyUI, Ollama et autres services d'IA exposés dans votre environnement. Les équipes DevSecOps doivent imposer la segmentation réseau et les règles de pare-feu avant de déployer ces outils. Le botnet NadMesh rappelle clairement qu'un déploiement rapide sans revue de sécurité invite à la récolte automatisée d'identifiants.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html)**
