---
title: "DragonForce Uses Microsoft Teams Relays to Hide Backdoor.Turn C2 Traffic"
date: "2026-06-19T11:15:07Z"
original_date: "2026-06-18T13:30:07"
lang: "en"
translationKey: "dragonforce-uses-microsoft-teams-relays-to-hide-backdoor-turn-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "DragonForce ransomware group deploys custom Go-based RAT Backdoor.Turn, concealing C2 traffic within Microsoft Teams relays, targeting a major U.S. services firm."
original_url: "https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html"
source: "The Hacker News"
severity: "High"
target: "Major U.S. services firm"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

DragonForce ransomware group deploys custom Go-based RAT Backdoor.Turn, concealing C2 traffic within Microsoft Teams relays, targeting a major U.S. services firm.

{{< cyber-report severity="High" source="The Hacker News" target="Major U.S. services firm" >}}

Threat actors associated with the DragonForce ransomware group have been observed using a custom Go-based remote access trojan (RAT) called Backdoor.Turn to conceal command-and-control (C2) traffic inside Microsoft Teams relay infrastructure. The backdoor was deployed against a major U.S. services firm, according to findings from Broadcom-owned Symantec and Carbon Black.

{{< ad-banner >}}

By leveraging legitimate Microsoft Teams relays, the attackers can blend malicious traffic with normal business communications, making detection more difficult for network defenders. The Go-based RAT provides the attackers with persistent access and the ability to execute commands, exfiltrate data, and deploy additional payloads.

This technique highlights the evolving tactics of ransomware groups to evade traditional network monitoring tools. Organizations using Microsoft Teams should review their security configurations and monitor for anomalous relay traffic patterns.

{{< netrunner-insight >}}

SOC analysts should monitor for unusual Microsoft Teams relay traffic, especially from non-standard endpoints or during off-hours. DevSecOps teams should enforce strict application allowlisting and inspect Teams traffic for encrypted tunnels that may indicate C2 communication. This attack underscores the need for zero-trust principles even for trusted collaboration platforms.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html)**
