---
title: "VerdantBamboo Deploys BSD Variant of BRICKSTORM on Linux Appliances"
date: "2026-06-08T11:51:53Z"
original_date: "2026-06-08T10:27:32"
lang: "en"
translationKey: "verdantbamboo-deploys-bsd-variant-of-brickstorm-on-linux-appliances"
author: "NewsBot (Validated by Federico Sella)"
description: "China-nexus group VerdantBamboo targets Linux systems with BSD variant of BRICKSTORM backdoor, plus PLENET and AGENTPSD malware."
original_url: "https://thehackernews.com/2026/06/verdantbamboo-deploys-bsd-variant-of.html"
source: "The Hacker News"
severity: "High"
target: "Linux appliances"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

China-nexus group VerdantBamboo targets Linux systems with BSD variant of BRICKSTORM backdoor, plus PLENET and AGENTPSD malware.

{{< cyber-report severity="High" source="The Hacker News" target="Linux appliances" >}}

A China-nexus cyber espionage group tracked as VerdantBamboo has been observed deploying a BSD variant of the known backdoor BRICKSTORM, along with two other malware families codenamed PLENET (aka GRIMBOLT) and AGENTPSD, targeting Linux systems. The activity was attributed by Volexity, which notes overlaps with hacking groups known as Clay Typhoon (Microsoft).

{{< ad-banner >}}

The use of a BSD variant of BRICKSTORM on Linux appliances indicates the group's adaptability and focus on compromising network edge devices. The additional malware families, PLENET and AGENTPSD, suggest a multi-tool approach to maintain persistence and exfiltrate data.

Organizations should monitor for indicators of compromise associated with these malware families and review their Linux appliance security posture. The campaign underscores the persistent threat from state-sponsored groups targeting critical infrastructure and enterprise networks.

{{< netrunner-insight >}}

For SOC analysts, prioritize monitoring for unusual outbound connections from Linux appliances and inspect for BRICKSTORM, PLENET, or AGENTPSD signatures. DevSecOps engineers should harden appliance configurations, enforce least-privilege access, and ensure robust logging to detect lateral movement. This campaign highlights the need for proactive threat hunting on network edge devices.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/06/verdantbamboo-deploys-bsd-variant-of.html)**
