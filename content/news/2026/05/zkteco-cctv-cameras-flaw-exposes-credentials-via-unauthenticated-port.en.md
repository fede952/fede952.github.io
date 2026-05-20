---
title: "ZKTeco CCTV Cameras Flaw Exposes Credentials via Unauthenticated Port"
date: "2026-05-20T10:24:09Z"
original_date: "2026-05-19T12:00:00"
lang: "en"
translationKey: "zkteco-cctv-cameras-flaw-exposes-credentials-via-unauthenticated-port"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of CVE-2026-8598 in ZKTeco CCTV cameras, allowing credential theft via an undocumented port. Patch available in firmware V5.0.1.2.20260421."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04"
source: "CISA"
severity: "Critical"
target: "ZKTeco CCTV Cameras"
cve: "CVE-2026-8598"
cvss: 9.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of CVE-2026-8598 in ZKTeco CCTV cameras, allowing credential theft via an undocumented port. Patch available in firmware V5.0.1.2.20260421.

{{< cyber-report severity="Critical" source="CISA" target="ZKTeco CCTV Cameras" cve="CVE-2026-8598" cvss="9.1" >}}

CISA has published an advisory (ICSA-26-139-04) detailing a critical authentication bypass vulnerability in ZKTeco CCTV cameras. The flaw, tracked as CVE-2026-8598, involves an undocumented configuration export port that is accessible without authentication. Successful exploitation could lead to information disclosure, including the capture of camera account credentials.

{{< ad-banner >}}

The vulnerability affects ZKTeco SSC335-GC2063-Face-0b77 Solution firmware versions prior to V5.0.1.2.20260421. The CVSS v3 base score is 9.1, indicating critical severity. The affected devices are deployed worldwide across commercial facilities, with the vendor headquartered in China.

ZKTeco has released a patched firmware version V5.0.1.2.20260421 to address the issue. Users are strongly advised to upgrade immediately. The vulnerability is classified under CWE-288 (Authentication Bypass Using an Alternate Path or Channel).

{{< netrunner-insight >}}

This is a textbook example of an exposed debug interface becoming a backdoor. SOC analysts should immediately scan for ZKTeco cameras on their network and verify firmware versions. For DevSecOps, this underscores the need to disable or firewall undocumented ports in IoT firmware builds. Treat any camera with firmware below V5.0.1.2.20260421 as compromised until proven otherwise.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04)**
