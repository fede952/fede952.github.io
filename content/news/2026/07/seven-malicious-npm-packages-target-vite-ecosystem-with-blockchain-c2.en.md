---
title: "Seven Malicious npm Packages Target Vite Ecosystem with Blockchain C2"
date: "2026-07-19T09:03:59Z"
original_date: "2026-07-17T18:54:51"
lang: "en"
translationKey: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
slug: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
author: "NewsBot (Validated by Federico Sella)"
description: "Checkmarx uncovers ViteVenom campaign using blockchain-based C2 infrastructure to deliver a RAT via seven malicious npm packages targeting Vite frontend tooling."
original_url: "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
source: "The Hacker News"
severity: "High"
target: "Vite frontend tooling ecosystem"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Checkmarx uncovers ViteVenom campaign using blockchain-based C2 infrastructure to deliver a RAT via seven malicious npm packages targeting Vite frontend tooling.

{{< cyber-report severity="High" source="The Hacker News" target="Vite frontend tooling ecosystem" >}}

Cybersecurity researchers from Checkmarx have identified a cluster of seven malicious npm packages targeting the Vite frontend tooling ecosystem as part of a software supply chain attack. The campaign, codenamed ViteVenom, represents an expansion of the previously observed ChainVeil operation, which utilized an unprecedented four-tier blockchain-based command-and-control (C2) infrastructure spanning the Tron network.

{{< ad-banner >}}

The malicious packages are designed to deliver a remote access trojan (RAT) to compromised systems, enabling attackers to exfiltrate data and maintain persistent access. The use of blockchain for C2 communications makes detection and takedown more challenging, as the infrastructure is decentralized and resistant to traditional sinkholing techniques.

Organizations using Vite in their development pipelines should immediately audit their dependencies for the identified malicious packages and implement strict package integrity checks. This incident highlights the growing sophistication of software supply chain attacks, where attackers leverage legitimate development tools and decentralized networks to evade detection.

{{< netrunner-insight >}}

For SOC analysts, monitoring outbound connections to blockchain nodes and unusual DNS queries can help detect this C2 technique. DevSecOps teams should enforce package signing and use dependency scanning tools to block known malicious packages before they enter the build pipeline.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html)**
