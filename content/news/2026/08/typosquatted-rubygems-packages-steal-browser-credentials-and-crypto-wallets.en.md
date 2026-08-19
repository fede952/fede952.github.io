---
title: "Typosquatted RubyGems Packages Steal Browser Credentials and Crypto Wallets"
date: "2026-08-19T07:36:21Z"
original_date: "2026-08-18T11:20:00"
lang: "en"
translationKey: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
slug: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
author: "NewsBot (Validated by Federico Sella)"
description: "Researchers flag 16 typosquatted RubyGems packages that deploy a Windows-based info stealer, targeting browser credentials and crypto wallets."
original_url: "https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html"
source: "The Hacker News"
severity: "High"
target: "RubyGems users on Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Researchers flag 16 typosquatted RubyGems packages that deploy a Windows-based info stealer, targeting browser credentials and crypto wallets.

{{< cyber-report severity="High" source="The Hacker News" target="RubyGems users on Windows" >}}

Cybersecurity researchers have uncovered a new typosquatting campaign targeting RubyGems users, deploying a Windows-based information stealer. The campaign, tracked as StubMaker, was discovered on August 15, 2026, by OpenSourceMalware, and involves 16 malicious packages designed to steal browser credentials and cryptocurrency wallets.

{{< ad-banner >}}

The malicious packages, which include names like 'ubnuler', 'ubnlder', 'ri18nr', 'reaker', 'rakier', 'orakw', and 'joxn', are likely typosquats of popular gems, tricking developers into installing them. Once installed, the stealer harvests sensitive data from browsers and crypto wallet extensions, posing a significant supply chain risk.

This campaign highlights the ongoing threat of typosquatting in open-source ecosystems. Developers are advised to verify package names carefully, use trusted sources, and monitor for suspicious dependencies in their projects.

{{< netrunner-insight >}}

For SOC analysts, this campaign underscores the need to monitor for unexpected RubyGems installations and network calls to suspicious domains. DevSecOps engineers should enforce strict dependency pinning and use tools that scan for typosquatted packages. Additionally, consider blocking known malicious package names and educating developers on typosquatting risks.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html)**
