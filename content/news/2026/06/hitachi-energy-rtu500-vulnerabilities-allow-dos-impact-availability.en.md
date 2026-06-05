---
title: "Hitachi Energy RTU500 Vulnerabilities Allow DoS, Impact Availability"
date: "2026-06-05T10:46:09Z"
original_date: "2026-06-04T12:00:00"
lang: "en"
translationKey: "hitachi-energy-rtu500-vulnerabilities-allow-dos-impact-availability"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of multiple vulnerabilities in Hitachi Energy RTU500 series, including NULL pointer dereference and infinite loop, with CVSS 7.8. Affected versions listed."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04"
source: "CISA"
severity: "High"
target: "Hitachi Energy RTU500 series CMU Firmware"
cve: "CVE-2025-69421"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of multiple vulnerabilities in Hitachi Energy RTU500 series, including NULL pointer dereference and infinite loop, with CVSS 7.8. Affected versions listed.

{{< cyber-report severity="High" source="CISA" target="Hitachi Energy RTU500 series CMU Firmware" cve="CVE-2025-69421" cvss="7.8" >}}

Hitachi Energy has disclosed multiple vulnerabilities affecting its RTU500 series CMU firmware. The flaws include NULL pointer dereference, integer overflow or wraparound, and loop with unreachable exit condition (infinite loop), which could lead to denial of service conditions. Exploitation primarily impacts product availability, with potential secondary effects on confidentiality and integrity.

{{< ad-banner >}}

The advisory, published by CISA (ICSA-26-155-04), lists affected firmware versions ranging from 12.7.1 to 13.8.1. Multiple CVEs are associated, including CVE-2025-69421, CVE-2026-24515, CVE-2026-25210, CVE-2026-32776, CVE-2026-32777, CVE-2026-32778, and CVE-2026-8479. The vulnerabilities have a CVSS v3 base score of 7.8, indicating high severity.

Hitachi Energy recommends immediate action per the advisory's remediation guidance. Given the critical infrastructure context, organizations using affected RTU500 versions should prioritize patching and implement network segmentation to mitigate exploitation risk.

{{< netrunner-insight >}}

These vulnerabilities are a reminder that OT devices often lag in patch cycles. SOC teams should monitor for anomalous traffic to RTU500 units and ensure these devices are isolated from untrusted networks. DevSecOps engineers should integrate firmware scanning into CI/CD pipelines to catch known CVEs before deployment.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04)**
