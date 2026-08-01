---
title: "HollowFrame Loader and Matryoshka Backdoor Target Law Firm"
date: "2026-08-01T09:01:20Z"
original_date: "2026-07-31T16:39:31"
lang: "en"
translationKey: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
slug: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
author: "NewsBot (Validated by Federico Sella)"
description: "New Go-based loader HollowFrame and Rust-based Matryoshka backdoor used in spear-phishing attack on a law firm, according to Blackpoint Cyber."
original_url: "https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html"
source: "The Hacker News"
severity: "High"
target: "Law firm"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

New Go-based loader HollowFrame and Rust-based Matryoshka backdoor used in spear-phishing attack on a law firm, according to Blackpoint Cyber.

{{< cyber-report severity="High" source="The Hacker News" target="Law firm" >}}

Blackpoint Cyber has uncovered a novel attack chain targeting a law firm, beginning with a spear-phishing email that lures the recipient to download an encrypted archive. The archive contains a Windows Shortcut (LNK) file, which, when executed, initiates a multi-stage infection process.

{{< ad-banner >}}

The attack leverages two previously undocumented malware families: HollowFrame, a Go-based loader framework, and Matryoshka, a Rust-based backdoor. The loader is responsible for delivering the backdoor, which provides the attackers with remote access to the compromised system.

This campaign highlights the continued evolution of malware tooling, with attackers adopting cross-platform languages like Go and Rust to evade detection and complicate analysis. The use of encrypted archives and LNK files in spear-phishing is a common tactic, but the combination of these specific tools adds a new layer of sophistication.

{{< netrunner-insight >}}

SOC analysts should prioritize monitoring for LNK file executions and archive downloads from email links, as these are early indicators of this attack chain. DevSecOps teams should consider blocking or sandboxing execution of files from encrypted archives, and ensure endpoint detection and response (EDR) solutions are tuned to detect Go and Rust binaries exhibiting loader behavior.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html)**
