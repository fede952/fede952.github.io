---
title: "Une faille Ill Bloom draine 3,1 millions de dollars de portefeuilles crypto via des phrases de récupération faibles"
date: "2026-07-10T10:19:16Z"
original_date: "2026-07-10T09:00:05"
lang: "fr"
translationKey: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
slug: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
author: "NewsBot (Validated by Federico Sella)"
description: "Des attaquants exploitent une vulnérabilité dans la génération de phrases de récupération de portefeuilles de cryptomonnaies, baptisée Ill Bloom, pour voler 3,1 millions de dollars lors d'une opération coordonnée."
original_url: "https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html"
source: "The Hacker News"
severity: "High"
target: "portefeuilles de cryptomonnaies"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Des attaquants exploitent une vulnérabilité dans la génération de phrases de récupération de portefeuilles de cryptomonnaies, baptisée Ill Bloom, pour voler 3,1 millions de dollars lors d'une opération coordonnée.

{{< cyber-report severity="High" source="The Hacker News" target="portefeuilles de cryptomonnaies" >}}

La société de sécurité Coinspect a divulgué une vulnérabilité dans un logiciel de portefeuille de cryptomonnaies, nommée Ill Bloom, qui permet aux attaquants de vider des fonds en exploitant une faible aléatoire dans la génération de phrases de récupération. La faille affecte la manière dont certains portefeuilles créent la phrase mnémonique qui contrôle l'accès aux fonds du portefeuille. Lorsque l'aléatoire est insuffisante, un attaquant peut calculer la phrase et obtenir un contrôle total sur le portefeuille.

{{< ad-banner >}}

Coinspect a confirmé que des attaquants ont déjà exploité cette vulnérabilité lors d'une opération coordonnée en mai, volant environ 3,1 millions de dollars à plusieurs portefeuilles. La date exacte et l'ampleur complète de l'attaque n'ont pas été divulguées, mais l'incident souligne l'importance cruciale d'une génération sécurisée de nombres aléatoires dans les applications cryptographiques.

Il est conseillé aux utilisateurs de portefeuilles de vérifier que leur logiciel utilise des générateurs de nombres aléatoires cryptographiquement sécurisés et d'envisager de transférer leurs fonds vers des portefeuilles dotés d'implémentations d'aléatoire auditées. Les développeurs doivent examiner leurs sources d'entropie et assurer la conformité aux normes de l'industrie comme BIP39.

{{< netrunner-insight >}}

Cet incident souligne le danger de se fier à une faible entropie dans la génération de clés cryptographiques. Les analystes SOC doivent surveiller les transactions inhabituelles de portefeuilles ou les mouvements de fonds massifs, tandis que les ingénieurs DevSecOps doivent auditer toute génération de nombres aléatoires dans les applications critiques pour la sécurité. Supposez toujours qu'une aléatoire prévisible sera exploitée.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html)**
