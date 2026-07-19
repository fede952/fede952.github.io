---
title: "La faille DDoS HollowByte gonfle la mémoire des serveurs OpenSSL avec une charge utile de 11 octets"
date: "2026-07-19T09:04:58Z"
original_date: "2026-07-17T17:56:21"
lang: "fr"
translationKey: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
slug: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
author: "NewsBot (Validated by Federico Sella)"
description: "Une vulnérabilité baptisée HollowByte permet à des attaquants non authentifiés de déclencher un déni de service sur les serveurs OpenSSL avec une charge utile malveillante de seulement 11 octets."
original_url: "https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/"
source: "BleepingComputer"
severity: "High"
target: "Serveurs OpenSSL"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Une vulnérabilité baptisée HollowByte permet à des attaquants non authentifiés de déclencher un déni de service sur les serveurs OpenSSL avec une charge utile malveillante de seulement 11 octets.

{{< cyber-report severity="High" source="BleepingComputer" target="Serveurs OpenSSL" >}}

Une vulnérabilité récemment découverte, nommée HollowByte, permet à des attaquants non authentifiés de provoquer un déni de service (DoS) sur les serveurs OpenSSL en envoyant une charge utile spécialement conçue de seulement 11 octets. La faille exploite des inefficacités d'allocation mémoire, provoquant un gonflement de la mémoire du serveur et épuisant finalement les ressources disponibles.

{{< ad-banner >}}

L'attaque ne nécessite pas d'authentification et peut être exécutée à distance, ce qui en fait une menace significative pour toute organisation utilisant OpenSSL pour des communications sécurisées. La taille minimale de la charge utile permet aux attaquants d'amplifier leur impact avec une bande passante limitée, submergeant potentiellement les serveurs avec un effort minimal.

Bien qu'aucun identifiant CVE n'ait encore été attribué, la vulnérabilité a été divulguée au projet OpenSSL et des correctifs sont attendus. En attendant, les administrateurs sont invités à surveiller l'utilisation de la mémoire et à mettre en œuvre des limitations de débit ou des règles de détection d'intrusion pour atténuer une éventuelle exploitation.

{{< netrunner-insight >}}

Pour les analystes SOC, il s'agit d'un vecteur DoS classique à faible bande passante et à fort impact qui peut contourner les défenses volumétriques traditionnelles. Les équipes DevSecOps devraient prioriser le déploiement des correctifs dès qu'ils seront disponibles et envisager de mettre en place des alertes de surveillance mémoire pour détecter une croissance anormale. La charge utile de 11 octets en fait un candidat idéal pour l'inclusion dans les règles de détection des menaces.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/)**
