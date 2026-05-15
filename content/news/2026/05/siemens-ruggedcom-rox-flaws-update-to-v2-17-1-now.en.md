---
title: "Siemens Ruggedcom ROX Flaws: Update to v2.17.1 Now"
date: "2026-05-15T09:41:40Z"
original_date: "2026-05-14T12:00:00"
lang: "en"
translationKey: "siemens-ruggedcom-rox-flaws-update-to-v2-17-1-now"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of multiple third-party vulnerabilities in Siemens Ruggedcom ROX before v2.17.1. Over 30 CVEs listed, including remote code execution risks. Immediate update advised."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16"
source: "CISA"
severity: "High"
target: "Siemens Ruggedcom ROX devices"
cve: "CVE-2019-13103"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of multiple third-party vulnerabilities in Siemens Ruggedcom ROX before v2.17.1. Over 30 CVEs listed, including remote code execution risks. Immediate update advised.

{{< cyber-report severity="High" source="CISA" target="Siemens Ruggedcom ROX devices" cve="CVE-2019-13103" >}}

Siemens Ruggedcom ROX versions prior to 2.17.1 contain multiple third-party vulnerabilities, as disclosed in CISA advisory ICSA-26-134-16. The affected products include RUGGEDCOM ROX MX5000, MX5000RE, and RX1400 series. Siemens has released updated versions to remediate these issues and strongly recommends upgrading to the latest release.

{{< ad-banner >}}

The advisory lists over 30 CVEs spanning from 2019 to 2025, including CVE-2019-13103, CVE-2022-2347, and CVE-2025-0395. While specific CVSS scores are not provided, the breadth and age of the vulnerabilities suggest a significant attack surface. Many of these CVEs are associated with third-party components and could lead to remote code execution, denial of service, or information disclosure.

Organizations using affected Ruggedcom ROX devices should prioritize patching, especially if the devices are exposed to untrusted networks. Given the industrial nature of these products, unpatched systems could be leveraged for lateral movement or disruption of critical infrastructure.

{{< netrunner-insight >}}

This is a classic case of accumulated technical debt in embedded systems. SOC analysts should inventory all Ruggedcom ROX instances and verify firmware versions. DevSecOps teams must integrate automated CVE scanning into their CI/CD for third-party dependencies. The lack of CVSS scores is concerning—assume worst-case and treat these as critical until proven otherwise.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16)**
