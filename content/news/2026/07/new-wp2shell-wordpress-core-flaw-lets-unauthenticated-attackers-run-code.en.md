---
title: "New wp2shell WordPress Core Flaw Lets Unauthenticated Attackers Run Code"
date: "2026-07-18T08:47:36Z"
original_date: "2026-07-17T21:20:10"
lang: "en"
translationKey: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
slug: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
author: "NewsBot (Validated by Federico Sella)"
description: "An anonymous HTTP request can execute code on WordPress sites. The bug affects core, so even bare installs are exploitable. Every 6.9 and 7.0 site was in range until patched."
original_url: "https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html"
source: "The Hacker News"
severity: "Critical"
target: "WordPress core (versions 6.9 and 7.0)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

An anonymous HTTP request can execute code on WordPress sites. The bug affects core, so even bare installs are exploitable. Every 6.9 and 7.0 site was in range until patched.

{{< cyber-report severity="Critical" source="The Hacker News" target="WordPress core (versions 6.9 and 7.0)" >}}

A critical unauthenticated remote code execution vulnerability has been discovered in WordPress core, affecting versions 6.9 and 7.0. The flaw, dubbed wp2shell, allows an attacker to execute arbitrary code on a target site by sending a specially crafted HTTP request. Notably, the vulnerability exists in the core software, meaning even a fresh WordPress installation with no plugins is exploitable.

{{< ad-banner >}}

The full technical details and a working proof-of-concept have been published, along with CVE identifiers assigned to the two underlying flaws. A persistent-object-cache condition has also been identified, which may complicate exploitation in certain environments. All sites running the affected versions were considered at risk until patches were applied.

Administrators are urged to update to the latest patched version immediately. Given the ease of exploitation and the widespread use of WordPress, this vulnerability poses a significant threat to web security. Organizations should prioritize patching and review their web application firewall rules to detect and block exploit attempts.

{{< netrunner-insight >}}

This is a textbook example of why core software must be hardened against unauthenticated attacks. SOC analysts should immediately scan for WordPress 6.9 and 7.0 instances and verify patching status. DevSecOps teams should treat this as a reminder to implement runtime application self-protection (RASP) and monitor for anomalous HTTP requests targeting wp-admin or wp-includes.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html)**
