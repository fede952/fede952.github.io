---
title: "DragonForce ransomware uses Microsoft Teams relays to hide C2 traffic"
date: "2026-06-16T12:10:12Z"
original_date: "2026-06-16T10:18:48"
lang: "en"
translationKey: "dragonforce-ransomware-uses-microsoft-teams-relays-to-hide-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "DragonForce ransomware deploys custom malware 'Backdoor.Turn' to conceal command-and-control traffic within Microsoft Teams relay infrastructure."
original_url: "https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/"
source: "BleepingComputer"
severity: "High"
target: "Microsoft Teams relay infrastructure"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

DragonForce ransomware deploys custom malware 'Backdoor.Turn' to conceal command-and-control traffic within Microsoft Teams relay infrastructure.

{{< cyber-report severity="High" source="BleepingComputer" target="Microsoft Teams relay infrastructure" >}}

The DragonForce ransomware group has been observed using a custom malware named 'Backdoor.Turn' to hide its command-and-control (C2) traffic within Microsoft Teams relay infrastructure. This technique allows the attackers to blend malicious communications with legitimate Teams traffic, making detection more difficult for network defenders.

{{< ad-banner >}}

By abusing Microsoft Teams relays, the ransomware gang can bypass traditional network security controls that may not scrutinize traffic to trusted services. The malware likely leverages Teams APIs or protocols to tunnel C2 data, evading signature-based detection and allowing persistent access to compromised networks.

Organizations using Microsoft Teams should monitor for unusual outbound traffic patterns to Teams endpoints and consider implementing additional inspection for encrypted tunnels. This incident highlights the growing trend of ransomware groups adopting living-off-the-land and trusted service abuse techniques to evade detection.

{{< netrunner-insight >}}

For SOC analysts, this underscores the need to baseline normal Teams traffic and alert on anomalies such as unexpected data volumes or connections to non-standard Teams endpoints. DevSecOps teams should review Teams integration permissions and restrict unnecessary API access to reduce the attack surface for relay abuse.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)**
