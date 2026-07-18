---
title: "La faille HollowByte d'OpenSSL gèle la mémoire avec des requêtes TLS de 11 octets"
date: "2026-07-18T08:44:53Z"
original_date: "2026-07-17T20:20:53"
lang: "fr"
translationKey: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
slug: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
author: "NewsBot (Validated by Federico Sella)"
description: "Un bogue de déni de service dans OpenSSL, surnommé HollowByte, permet aux attaquants de geler la mémoire du serveur à l'aide de minuscules requêtes TLS. L'équipe rouge d'Okta l'a signalé ; le correctif a été livré sans CVE."
original_url: "https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html"
source: "The Hacker News"
severity: "High"
target: "Serveurs OpenSSL sur systèmes glibc"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un bogue de déni de service dans OpenSSL, surnommé HollowByte, permet aux attaquants de geler la mémoire du serveur à l'aide de minuscules requêtes TLS. L'équipe rouge d'Okta l'a signalé ; le correctif a été livré sans CVE.

{{< cyber-report severity="High" source="The Hacker News" target="Serveurs OpenSSL sur systèmes glibc" >}}

Une vulnérabilité de déni de service récemment divulguée dans OpenSSL, nommée HollowByte par l'équipe rouge d'Okta, permet à un attaquant d'épuiser la mémoire du serveur avec seulement 11 octets de données d'établissement de liaison TLS. Le défaut amène un serveur OpenSSL non corrigé à allouer jusqu'à 131 Ko de mémoire pour un message qui n'arrive jamais, et sur les systèmes utilisant glibc, cette mémoire n'est pas libérée tant que le processus n'est pas redémarré.

{{< ad-banner >}}

OpenSSL a livré le correctif en juin 2026 sans attribuer d'identifiant CVE, sans publier d'avis ni noter le changement dans le journal des modifications. L'équipe rouge d'Okta, qui a découvert et signalé le bogue, a publié les détails après la sortie du correctif. La vulnérabilité affecte les serveurs OpenSSL fonctionnant sur des systèmes basés sur glibc, les rendant susceptibles aux attaques par épuisement de la mémoire.

Bien que l'attaque ne nécessite qu'un seul ClientHello TLS de 11 octets, l'impact peut être grave dans les environnements où les processus OpenSSL sont de longue durée et gèrent de nombreuses connexions simultanées. Les organisations utilisant OpenSSL sur glibc devraient prioriser l'application de la mise à jour de juin 2026 pour prévenir d'éventuelles conditions de déni de service.

{{< netrunner-insight >}}

Il s'agit d'un vecteur classique d'épuisement des ressources qui contourne la limitation de débit traditionnelle car le trafic malveillant ressemble à des établissements de liaison TLS normaux. Les analystes SOC doivent surveiller les pics soudains d'utilisation de la mémoire sur les serveurs OpenSSL, et les équipes DevSecOps doivent vérifier que la mise à jour OpenSSL de juin 2026 est déployée, même sans CVE. L'absence de CVE ne réduit pas le risque opérationnel—traitez ce correctif comme une priorité élevée.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html)**
