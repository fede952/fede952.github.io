---
title: "Malicious npm Packages Target Alibaba Tool Users with Cross-Platform RAT"
date: "2026-08-04T09:40:19Z"
original_date: "2026-08-03T18:43:53"
lang: "en"
translationKey: "malicious-npm-packages-target-alibaba-tool-users-with-cross-platform-rat"
slug: "malicious-npm-packages-target-alibaba-tool-users-with-cross-platform-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Researchers uncover 18 malicious npm packages, including 'lib-mtop', delivering a cross-platform RAT to Alibaba developer tool users in a targeted supply chain attack."
original_url: "https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html"
source: "The Hacker News"
severity: "High"
target: "Alibaba developer tool users"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Researchers uncover 18 malicious npm packages, including 'lib-mtop', delivering a cross-platform RAT to Alibaba developer tool users in a targeted supply chain attack.

{{< cyber-report severity="High" source="The Hacker News" target="Alibaba developer tool users" >}}

Cybersecurity researchers have identified a new set of 18 malicious npm packages designed to target users of Alibaba developer tools. The attack is part of a sophisticated, targeted software supply chain campaign that specifically focuses on Chinese-speaking environments, indicating a high level of reconnaissance and localization.

{{< ad-banner >}}

One of the packages, 'lib-mtop', is an unscoped package that shares the same name as a private Alibaba package, a classic typosquatting technique. This suggests the attackers are attempting to deceive developers who might mistakenly install the malicious package instead of the legitimate one, thereby gaining a foothold in their development environments.

The malicious packages deliver a cross-platform remote access trojan (RAT) to the victims, which can provide the attackers with remote control over the compromised systems. The cross-platform nature of the RAT indicates that it is designed to affect a wide range of operating systems, increasing the potential impact of the attack.

{{< netrunner-insight >}}

This attack underscores the importance of verifying package authenticity, especially when using private or internal packages. SOC analysts and DevSecOps engineers should implement strict package provenance checks, such as using lock files and verifying package integrity, and monitor for unexpected network connections from development machines. Additionally, consider using a private registry with allowlists to prevent typosquatting attacks.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html)**
