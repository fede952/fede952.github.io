---
title: "BdThemes Supply Chain Attack Creates Rogue WordPress Admins"
date: "2026-08-11T08:10:19Z"
original_date: "2026-08-11T05:48:44"
lang: "en"
translationKey: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
slug: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
author: "NewsBot (Validated by Federico Sella)"
description: "Supply chain compromise hits BdThemes WordPress plugins; zero source code modified, but malicious JSON creates rogue admin accounts."
original_url: "https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html"
source: "The Hacker News"
severity: "High"
target: "WordPress sites using BdThemes plugins"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Supply chain compromise hits BdThemes WordPress plugins; zero source code modified, but malicious JSON creates rogue admin accounts.

{{< cyber-report severity="High" source="The Hacker News" target="WordPress sites using BdThemes plugins" >}}

Cybersecurity researchers have disclosed a supply chain attack targeting BdThemes, a WordPress plugin vendor. The compromise led to the temporary disabling of plugin downloads by the WordPress plugins team. Notably, the attack deviates from typical supply chain incidents: no source code files within the official WordPress.org repository were modified.

{{< ad-banner >}}

Instead, the attack leverages malicious JSON payloads to create rogue WordPress administrator accounts. This technique allows attackers to gain unauthorized access to affected sites without altering the core plugin files, making detection more challenging for standard integrity checks.

Wordfence researcher Paolo Tresso highlighted the unusual nature of the attack, emphasizing that the absence of source code modifications underscores the need for comprehensive supply chain monitoring beyond just code integrity.

{{< netrunner-insight >}}

This attack underscores the importance of monitoring not just code changes but also configuration and data files like JSON. For SOC analysts, treat plugin updates as high-risk events and verify the integrity of all files, not just source code. DevSecOps should implement runtime monitoring for unexpected admin account creation and consider file integrity monitoring that covers non-code assets.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html)**
