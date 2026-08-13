---
title: "August 2026 Patch Tuesday: 421 Flaws, Lazarus Zero-Day, and 4 RCEs with CVSS 9.8"
date: "2026-08-13T08:21:14Z"
original_date: "2026-08-12T08:28:22"
lang: "en"
translationKey: "august-2026-patch-tuesday-421-flaws-lazarus-zero-day-and-4-rces-with-cvss-9-8"
slug: "august-2026-patch-tuesday-421-flaws-lazarus-zero-day-and-4-rces-with-cvss-9-8"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft's August 2026 Patch Tuesday addresses 421 vulnerabilities, including a WinSock driver zero-day exploited by Lazarus and four unauthenticated RCEs with CVSS 9.8."
original_url: "https://www.cybersecurity360.it/news/patch-tuesday-agosto-2026-un-driver-windows-il-gruppo-lazarus-e-400-vulnerabilita-sullo-sfondo/"
source: "Cybersecurity360"
severity: "Critical"
target: "Microsoft Windows WinSock driver"
cve: null
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft's August 2026 Patch Tuesday addresses 421 vulnerabilities, including a WinSock driver zero-day exploited by Lazarus and four unauthenticated RCEs with CVSS 9.8.

{{< cyber-report severity="Critical" source="Cybersecurity360" target="Microsoft Windows WinSock driver" cvss="9.8" >}}

Microsoft's August 2026 Patch Tuesday addresses a total of 421 vulnerabilities, marking a significant update. Among these, a zero-day vulnerability in the Windows WinSock driver has been actively exploited by the Lazarus Group, a well-known North Korean threat actor. This zero-day is particularly concerning as it allows attackers to gain elevated privileges or execute arbitrary code, potentially compromising affected systems.

{{< ad-banner >}}

In addition to the zero-day, the update includes four unauthenticated remote code execution (RCE) vulnerabilities, all rated with a CVSS score of 9.8. These critical flaws could be exploited remotely without any user interaction, making them high-priority for immediate patching. The sheer volume of vulnerabilities underscores the importance of a robust patch management process.

The article also highlights a shift in vulnerability management strategies, noting that with the adoption of AI-driven discovery, context-based triage is becoming more effective than traditional score-based triage. This suggests that organizations should prioritize vulnerabilities based on their specific environment and threat landscape, rather than relying solely on CVSS scores.

{{< netrunner-insight >}}

For SOC analysts, the Lazarus zero-day in WinSock should be treated as an immediate priority, as it is already being exploited. Patch it across all Windows endpoints without delay. DevSecOps teams should leverage AI-driven context to triage the 421 vulnerabilities, focusing on those that are internet-facing or critical to business operations, rather than just chasing high CVSS scores. Remember, the four RCEs with CVSS 9.8 are unauthenticated, so they should be patched before any other non-critical updates.

{{< /netrunner-insight >}}

---

**[Read full article on Cybersecurity360 ›](https://www.cybersecurity360.it/news/patch-tuesday-agosto-2026-un-driver-windows-il-gruppo-lazarus-e-400-vulnerabilita-sullo-sfondo/)**
