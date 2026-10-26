---
title: "Calculateur CVSS 4.0 (et CVSS 3.1)"
description: "Calculez le score CVSS 4.0 avec la méthode MacroVector officielle du FIRST, ou les scores CVSS 3.1 de base, temporel et environnemental, en local."
intro: "Choisissez les métriques ou collez une chaîne de vecteur pour obtenir le score **CVSS 4.0**, la sévérité, la nomenclature (CVSS-B, BT, BE ou BTE) et le MacroVector, calculés avec **la logique de calcul et la table officielles du FIRST**. Un second onglet note les vecteurs **CVSS 3.1**, scores temporel et environnemental compris. Partagez un résultat avec un lien `?vector=`. Tout s'exécute dans votre navigateur."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["calculateur cvss 4.0", "calculateur cvss", "calculer score cvss", "calculateur cvss 3.1", "score cvss vulnérabilité", "vecteur cvss", "cvss 4 macrovector", "sévérité vulnérabilité cvss"]
tags: ["security", "vulnerability", "cvss", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/cvss-calculator/"
tool_title: "Calculateur CVSS 4.0 et 3.1"
tool_height: 1400
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Choisissez **CVSS 4.0** ou **CVSS 3.1** avec les onglets."
  - "Collez une **chaîne de vecteur** (par exemple tirée d'un avis de sécurité), ou cliquez sur la valeur de chaque métrique de base."
  - "Si besoin, ouvrez les métriques **de menace**, **environnementales** ou, en 4.0, **supplémentaires** pour adapter le score à votre environnement."
  - "Lisez le **score**, la **sévérité** et, en 4.0, la **nomenclature** qui indique quels groupes de métriques ont été utilisés."
  - "Appuyez sur **Copier le vecteur** pour vos rapports, ou **Copier le lien** pour partager une page qui s'ouvre avec le même vecteur."
faq:
  - q: "Le score est-il le même que celui du calculateur officiel du FIRST ?"
    a: "Il est calculé avec la même méthode : le code CVSS 4.0 de cet outil est un portage de la fonction de calcul du calculateur officiel du FIRST et utilise sa table des MacroVectors sans modification. Les tests vérifient tous les vecteurs d'exemple publiés sur la page d'exemples CVSS 4.0 du FIRST et comparent 20 000 vecteurs aléatoires au code officiel ; le CVSS 3.1 est comparé de la même façon au calculateur 3.1 du FIRST. Ce site n'est pas affilié au FIRST."
  - q: "Pourquoi CVSS 4.0 n'utilise-t-il pas une formule comme la 3.1 ?"
    a: "CVSS 4.0 regroupe les métriques en six ensembles d'équivalence et associe à chaque combinaison, un MacroVector, un score fixé par des experts. Le score final part de celui du MacroVector et il est ajusté selon la distance entre le vecteur et le vecteur le plus sévère du même MacroVector. C'est pourquoi l'outil affiche le MacroVector à côté du score."
  - q: "Que signifient CVSS-B, CVSS-BT, CVSS-BE et CVSS-BTE ?"
    a: "Ils indiquent quels groupes de métriques un score CVSS 4.0 inclut : B la base seule, T ajoute les métriques de menace (maturité de l'exploit), E ajoute les métriques environnementales. Le score de base d'un avis est CVSS-B ; avec les informations d'exploitation et votre propre environnement, il devient CVSS-BTE."
  - q: "Quelles sont les tranches de sévérité ?"
    a: "L'échelle qualitative est la même en CVSS 3.1 et 4.0 : Aucune 0.0, Faible 0.1–3.9, Moyenne 4.0–6.9, Élevée 7.0–8.9, Critique 9.0–10.0."
  - q: "Les métriques supplémentaires modifient-elles le score ?"
    a: "Non. Safety, Automatable, Recovery, Value Density, Vulnerability Response Effort et Provider Urgency ajoutent du contexte pour décider, mais n'influencent pas le score CVSS 4.0. Elles figurent quand même dans le vecteur."
  - q: "Quelque chose est-il envoyé à un serveur ?"
    a: "Non. Le calcul se fait dans votre navigateur et l'outil n'effectue aucune requête réseau. Un lien partagé ne contient que la chaîne de vecteur."
---

## Comment ça marche

### CVSS 4.0 : les MacroVectors et la table officielle

Les 11 métriques de base, plus la maturité de l'exploit et les exigences environnementales, sont réparties en six groupes d'équivalence (EQ1–EQ6), comme « à quel point le système est atteignable » (vecteur d'attaque, privilèges requis, interaction utilisateur) ou « quelle est la gravité de l'impact sur le système vulnérable ». Le niveau de chaque groupe forme un **MacroVector** à six chiffres, et la table du FIRST attribue un score à chacune des 270 valeurs possibles. Le score du vecteur est ce score moins un ajustement fondé sur sa distance au vecteur le plus sévère du même MacroVector, arrondi à une décimale. L'implémentation suit pas à pas le calculateur officiel du FIRST et utilise sa table telle que publiée (licence BSD-2-Clause, créditée dans le code source).

### Métriques environnementales et de menace

Si elle n'est pas renseignée, la **maturité de l'exploit** prend le pire cas (Attacked), et les exigences de sécurité valent High, comme le prévoit la spécification. Les métriques **modifiées** remplacent la métrique de base correspondante pour votre environnement : par exemple, un système joignable seulement depuis le réseau interne peut utiliser Modified Attack Vector: Adjacent.

### CVSS 3.1

Le second onglet applique les équations de la spécification CVSS 3.1 : le score de base à partir de l'impact et de l'exploitabilité (avec l'ajustement de portée), le score temporel à partir de la maturité du code d'exploit, du niveau de correction et de la fiabilité du signalement, et le score environnemental avec les métriques modifiées et la fonction d'arrondi de la 3.1.

## Cas d'usage

- **Trier les avis** — collez le vecteur d'une fiche CVE ou d'un bulletin d'éditeur et voyez ce qui détermine le score.
- **Noter vos découvertes** — pour un rapport de test d'intrusion ou une soumission de bug bounty, avec un vecteur vérifiable par d'autres.
- **Adapter à votre environnement** — utilisez les métriques environnementales pour classer différemment une même vulnérabilité sur des systèmes exposés à internet et internes.
- **Comparer 3.1 et 4.0** — beaucoup de bases publient encore les deux ; notez le même problème dans chaque onglet.
- **Apprendre les métriques** — chaque valeur est libellée, et le score se met à jour à chaque clic.
