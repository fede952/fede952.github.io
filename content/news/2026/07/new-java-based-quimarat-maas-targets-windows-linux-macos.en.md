---
title: "New Java-Based QuimaRAT MaaS Targets Windows, Linux, macOS"
date: "2026-07-06T11:23:53Z"
original_date: "2026-07-06T08:13:33"
lang: "en"
translationKey: "new-java-based-quimarat-maas-targets-windows-linux-macos"
slug: "new-java-based-quimarat-maas-targets-windows-linux-macos"
author: "NewsBot (Validated by Federico Sella)"
description: "QuimaRAT, a cross-platform Java RAT sold as malware-as-a-service, threatens Windows, Linux, and macOS systems. Researchers at LevelBlue detail its subscription model and capabilities."
original_url: "https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html"
source: "The Hacker News"
severity: "High"
target: "Windows, Linux, macOS systems"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

QuimaRAT, a cross-platform Java RAT sold as malware-as-a-service, threatens Windows, Linux, and macOS systems. Researchers at LevelBlue detail its subscription model and capabilities.

{{< cyber-report severity="High" source="The Hacker News" target="Windows, Linux, macOS systems" >}}

Cybersecurity researchers at LevelBlue have identified a new Java-based remote access trojan (RAT) named QuimaRAT, which is capable of targeting Windows, Linux, and macOS environments. The malware is being marketed under a malware-as-a-service (MaaS) model, with subscription tiers ranging from $150 for one month to $1,200 for lifetime access, as well as a $300 tier.

{{< ad-banner >}}

QuimaRAT's cross-platform nature, enabled by Java, allows it to compromise diverse operating systems, making it a versatile threat for organizations with heterogeneous environments. The MaaS model lowers the barrier for entry for less skilled threat actors, potentially increasing the frequency of attacks.

While specific technical details about QuimaRAT's capabilities are limited in the initial report, its Java-based architecture suggests it may leverage common techniques such as keylogging, screen capture, and file exfiltration. Organizations should monitor for suspicious Java processes and implement application allowlisting to mitigate the risk.

{{< netrunner-insight >}}

For SOC analysts, QuimaRAT's cross-platform nature means detection rules must cover Windows, Linux, and macOS endpoints. DevSecOps teams should review Java runtime usage and consider restricting execution of unsigned Java applications. Given the MaaS model, expect low-sophistication attackers to deploy this RAT, so baseline monitoring for unusual network connections and process behaviors is critical.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html)**
