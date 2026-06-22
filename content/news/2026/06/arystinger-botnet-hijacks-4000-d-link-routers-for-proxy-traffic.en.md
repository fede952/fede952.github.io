---
title: "AryStinger Botnet Hijacks 4,000+ D-Link Routers for Proxy Traffic"
date: "2026-06-22T12:48:45Z"
original_date: "2026-06-21T14:14:22"
lang: "en"
translationKey: "arystinger-botnet-hijacks-4000-d-link-routers-for-proxy-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "A new botnet named AryStinger has compromised over 4,000 outdated D-Link routers, turning them into proxies for malicious traffic. No CVE or CVSS data is available."
original_url: "https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/"
source: "BleepingComputer"
severity: "Medium"
target: "Outdated D-Link routers"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A new botnet named AryStinger has compromised over 4,000 outdated D-Link routers, turning them into proxies for malicious traffic. No CVE or CVSS data is available.

{{< cyber-report severity="Medium" source="BleepingComputer" target="Outdated D-Link routers" >}}

A previously undocumented malware botnet named AryStinger has compromised more than 4,000 outdated D-Link routers worldwide, according to a report by BleepingComputer. The botnet turns these devices into proxies for malicious traffic, allowing attackers to anonymize their activities and potentially launch further attacks.

{{< ad-banner >}}

The compromised routers are believed to be running outdated firmware with known vulnerabilities, though no specific CVE identifiers were disclosed in the report. The botnet's infrastructure and propagation methods remain under analysis, but the scale of the infection highlights the risks posed by unpatched IoT devices.

Organizations are advised to inventory their network devices, ensure firmware is up to date, and monitor for unusual traffic patterns that may indicate proxy usage. The lack of detailed technical indicators in the initial report suggests that further investigation is needed to develop detection signatures.

{{< netrunner-insight >}}

For SOC analysts, this is a reminder to monitor for unexpected outbound connections from network devices, especially older routers. DevSecOps teams should enforce firmware update policies and consider segmenting IoT devices from critical networks. Without specific IoCs, baseline traffic analysis and device fingerprinting are key to spotting such botnet activity.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/)**
