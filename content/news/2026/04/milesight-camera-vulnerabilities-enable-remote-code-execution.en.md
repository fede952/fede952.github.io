---
title: "Milesight Camera Vulnerabilities Enable Remote Code Execution"
date: "2026-04-29T07:21:59Z"
original_date: "2026-04-23T12:00:00"
lang: "en"
translationKey: "milesight-camera-vulnerabilities-enable-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of multiple Milesight camera models affected by critical vulnerabilities (CVE-2026-28747, etc.) that could lead to device crashes or remote code execution."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03"
source: "CISA"
severity: "Critical"
target: "Milesight IP Cameras"
cve: "CVE-2026-28747"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of multiple Milesight camera models affected by critical vulnerabilities (CVE-2026-28747, etc.) that could lead to device crashes or remote code execution.

{{< cyber-report severity="Critical" source="CISA" target="Milesight IP Cameras" cve="CVE-2026-28747" >}}

CISA has released an advisory (ICSA-26-113-03) detailing multiple vulnerabilities affecting a wide range of Milesight camera models. The flaws, identified as CVE-2026-28747, CVE-2026-27785, CVE-2026-32644, CVE-2026-32649, and CVE-2026-20766, impact firmware versions across several product lines including MS-Cxx63-PD, MS-Cxx64-xPD, and others. Successful exploitation could allow an attacker to crash the device or achieve remote code execution.

{{< ad-banner >}}

The affected models span multiple series, with firmware versions up to 51.7.0.77-r12, 3x.8.0.3-r11, 63.8.0.4-r3, and others. Given the critical nature of remote code execution, these vulnerabilities pose a significant risk to organizations using Milesight cameras in surveillance or IoT deployments. CISA recommends users apply available patches and follow vendor guidance to mitigate exposure.

While no CVSS scores or evidence of active exploitation are provided in the advisory, the potential for device compromise and network intrusion warrants immediate attention. Security teams should inventory affected camera models, segment IoT devices from critical networks, and prioritize firmware updates.

{{< netrunner-insight >}}

For SOC analysts, monitor for anomalous traffic from camera subnets and ensure these devices are isolated. DevSecOps engineers should expedite patching of all Milesight cameras, as remote code execution vulnerabilities in edge devices often become entry points for lateral movement. Treat these CVEs as critical until vendor patches are verified.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03)**
