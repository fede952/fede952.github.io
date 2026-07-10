---
title: "GigaWiper Backdoor Combines Disk Wiping, Fake Ransomware, and Spyware"
date: "2026-07-10T10:21:21Z"
original_date: "2026-07-09T18:08:07"
lang: "en"
translationKey: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
slug: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft uncovers GigaWiper, a modular Windows backdoor that bundles three destructive tools: disk wiper, fake ransomware, and spyware, posing a severe threat to endpoints."
original_url: "https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html"
source: "The Hacker News"
severity: "High"
target: "Windows endpoints"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft uncovers GigaWiper, a modular Windows backdoor that bundles three destructive tools: disk wiper, fake ransomware, and spyware, posing a severe threat to endpoints.

{{< cyber-report severity="High" source="The Hacker News" target="Windows endpoints" >}}

Microsoft has identified a new destructive Windows backdoor named GigaWiper, which integrates three older malicious programs into a single modular framework. The backdoor offers operators a menu of commands to choose from, each designed to inflict a different type of damage: full disk wiping, overwriting the Windows system drive, or executing fake ransomware that encrypts files with a key that is never saved.

{{< ad-banner >}}

The modular design of GigaWiper allows attackers to tailor their destructive actions based on the target environment. The inclusion of disk-wiping capabilities and fake ransomware suggests that the primary objective is to cause maximum disruption and data loss, rather than financial gain. This combination of techniques makes GigaWiper a versatile and dangerous tool for destructive cyber operations.

While the specific distribution vector remains undisclosed, the backdoor's ability to wipe entire disks and simulate ransomware attacks indicates a high level of sophistication. Organizations should prioritize endpoint detection and response (EDR) solutions and ensure robust backup strategies to mitigate the impact of such threats.

{{< netrunner-insight >}}

For SOC analysts, GigaWiper underscores the need for behavioral detection rules that flag mass file operations and disk-level writes. DevSecOps teams should validate backup integrity and test recovery procedures regularly, as fake ransomware can bypass traditional decryption approaches. Treat any unverified ransomware incident as a potential wiper attack until proven otherwise.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html)**
