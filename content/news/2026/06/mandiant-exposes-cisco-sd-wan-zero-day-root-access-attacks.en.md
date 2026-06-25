---
title: "Mandiant Exposes Cisco SD-WAN Zero-Day Root Access Attacks"
date: "2026-06-25T10:15:15Z"
original_date: "2026-06-24T21:29:10"
lang: "en"
translationKey: "mandiant-exposes-cisco-sd-wan-zero-day-root-access-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "New details reveal how hackers exploited CVE-2026-20245 in zero-day attacks to create rogue root accounts on Cisco Catalyst SD-WAN devices."
original_url: "https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/"
source: "BleepingComputer"
severity: "High"
target: "Cisco Catalyst SD-WAN devices"
cve: "CVE-2026-20245"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

New details reveal how hackers exploited CVE-2026-20245 in zero-day attacks to create rogue root accounts on Cisco Catalyst SD-WAN devices.

{{< cyber-report severity="High" source="BleepingComputer" target="Cisco Catalyst SD-WAN devices" cve="CVE-2026-20245" >}}

Mandiant has disclosed new technical details on how threat actors exploited a zero-day vulnerability in Cisco Catalyst SD-WAN software, tracked as CVE-2026-20245, to gain root access on targeted devices. The attacks involved creating rogue root accounts, allowing persistent unauthorized access.

{{< ad-banner >}}

The vulnerability, which was patched by Cisco in a recent advisory, was used in limited, targeted attacks. Mandiant's analysis reveals the specific exploitation chain, emphasizing the importance of applying security updates promptly.

Organizations using Cisco SD-WAN solutions are urged to audit their systems for signs of compromise, such as unauthorized accounts or unusual root-level activity. The incident underscores the critical need for robust patch management and monitoring of network infrastructure.

{{< netrunner-insight >}}

For SOC analysts, prioritize monitoring for unauthorized account creation and privilege escalation events on Cisco SD-WAN appliances. DevSecOps teams should ensure rapid deployment of Cisco's security patches and consider segmenting SD-WAN management interfaces to reduce attack surface.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/)**
