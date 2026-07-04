---
title: "PamStealer macOS Stealer Uses Fake Maccy Sites and PAM Checks"
date: "2026-07-04T09:17:53Z"
original_date: "2026-07-03T08:03:37"
lang: "en"
translationKey: "pamstealer-macos-stealer-uses-fake-maccy-sites-and-pam-checks"
author: "NewsBot (Validated by Federico Sella)"
description: "Jamf Threat Labs discovers PamStealer, a macOS info-stealer distributed via fake Maccy sites, using PAM checks to steal login passwords."
original_url: "https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html"
source: "The Hacker News"
severity: "High"
target: "macOS users"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Jamf Threat Labs discovers PamStealer, a macOS info-stealer distributed via fake Maccy sites, using PAM checks to steal login passwords.

{{< cyber-report severity="High" source="The Hacker News" target="macOS users" >}}

Cybersecurity researchers at Jamf Threat Labs have identified a new macOS information stealer named PamStealer. The malware is distributed as a compiled AppleScript (.scpt) file that impersonates Maccy, a legitimate open-source clipboard manager. It employs a series of clever tricks to infect systems and siphon sensitive data, including login passwords.

{{< ad-banner >}}

PamStealer gets its name from its ability to abuse the Pluggable Authentication Module (PAM) framework on macOS. By intercepting authentication processes, it can capture user credentials when they log in or authenticate for privileged operations. The stealer then exfiltrates the stolen data to attacker-controlled servers.

The campaign relies on fake websites and social engineering to trick users into downloading the malicious .scpt file. Once executed, the malware performs PAM checks to harvest passwords without raising suspicion. Organizations with macOS endpoints should monitor for unusual .scpt file executions and PAM-related anomalies.

{{< netrunner-insight >}}

For SOC analysts, this highlights the need to monitor for compiled AppleScript executions and PAM modifications on macOS endpoints. DevSecOps teams should enforce application whitelisting and educate users about verifying software sources, especially for clipboard managers. Implementing endpoint detection rules for PAM abuse can help catch this stealer early.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html)**
