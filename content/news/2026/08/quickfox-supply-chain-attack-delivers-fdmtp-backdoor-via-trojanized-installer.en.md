---
title: "QuickFox Supply Chain Attack Delivers FDMTP Backdoor via Trojanized Installer"
date: "2026-08-05T09:34:12Z"
original_date: "2026-08-05T05:47:19"
lang: "en"
translationKey: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
slug: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
author: "NewsBot (Validated by Federico Sella)"
description: "Long-running supply chain attack on QuickFox VPN trojanizes installer to deploy FDMTP backdoor, targeting overseas Chinese users since August 2025."
original_url: "https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html"
source: "The Hacker News"
severity: "High"
target: "QuickFox VPN users"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Long-running supply chain attack on QuickFox VPN trojanizes installer to deploy FDMTP backdoor, targeting overseas Chinese users since August 2025.

{{< cyber-report severity="High" source="The Hacker News" target="QuickFox VPN users" >}}

Fortinet FortiGuard Labs has disclosed a long-standing supply chain attack targeting QuickFox, a VPN and network acceleration tool popular among overseas Chinese users. The attack, active since at least August 2025, involves a trojanized version of the application's Windows installer that delivers a backdoor named FDMTP.

{{< ad-banner >}}

The trojanized installer is distributed through official or trusted channels, compromising the integrity of the software supply chain. Once executed, FDMTP provides attackers with remote access and control over the victim's system, potentially leading to data theft, surveillance, or further malware deployment.

This incident highlights the growing risk of supply chain attacks on niche but trusted tools, especially those serving specific communities. Organizations and individuals using QuickFox should verify the integrity of their installations and monitor for indicators of compromise associated with FDMTP.

{{< netrunner-insight >}}

This attack underscores the need for robust software integrity verification, even for tools from seemingly reputable vendors. SOC analysts should hunt for FDMTP indicators and monitor for unusual network connections from VPN clients. DevSecOps teams must enforce code signing and hash verification in their software deployment pipelines to mitigate such supply chain risks.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html)**
