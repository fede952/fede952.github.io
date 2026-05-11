---
title: "Microsoft Patch Tuesday April 2026: 167 Flaws, SharePoint Zero-Day, BlueHammer"
date: "2026-05-11T10:37:48Z"
original_date: "2026-04-14T21:47:59"
lang: "en"
translationKey: "microsoft-patch-tuesday-april-2026-167-flaws-sharepoint-zero-day-bluehammer"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft fixes 167 vulnerabilities including a SharePoint zero-day and a publicly disclosed Windows Defender flaw (BlueHammer). Google Chrome and Adobe Reader also patch actively exploited bugs."
original_url: "https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/"
source: "Krebs on Security"
severity: "Critical"
target: "Microsoft Windows, SharePoint, Windows Defender, Chrome, Adobe Reader"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft fixes 167 vulnerabilities including a SharePoint zero-day and a publicly disclosed Windows Defender flaw (BlueHammer). Google Chrome and Adobe Reader also patch actively exploited bugs.

{{< cyber-report severity="Critical" source="Krebs on Security" target="Microsoft Windows, SharePoint, Windows Defender, Chrome, Adobe Reader" >}}

Microsoft's April 2026 Patch Tuesday addresses a staggering 167 security vulnerabilities across Windows and related software. Among the most critical is a SharePoint Server zero-day vulnerability that could allow remote code execution, though no CVE identifier was provided in the report. Additionally, a publicly disclosed weakness in Windows Defender, dubbed 'BlueHammer,' has been fixed.

{{< ad-banner >}}

Separately, Google Chrome patched its fourth zero-day of 2026, continuing a trend of frequent browser updates. Adobe Reader also received an emergency update to address an actively exploited flaw that can lead to remote code execution. Organizations should prioritize these updates given active exploitation.

The sheer volume of patches this month underscores the importance of robust patch management processes. Security teams should focus on the SharePoint zero-day and the Windows Defender issue as immediate priorities, while also ensuring Chrome and Adobe Reader are updated across the enterprise.

{{< netrunner-insight >}}

For SOC analysts, prioritize the SharePoint zero-day and BlueHammer Windows Defender flaw for immediate patching, as they are either actively exploited or publicly known. DevSecOps teams should integrate these updates into their CI/CD pipelines and verify that endpoint protection tools are not disrupted by the Defender fix. The Chrome and Adobe Reader patches also warrant urgent attention given their active exploitation status.

{{< /netrunner-insight >}}

---

**[Read full article on Krebs on Security ›](https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/)**
