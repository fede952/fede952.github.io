---
title: "Siemens Teamcenter Flaws Risk Availability, Integrity, Confidentiality"
date: "2026-05-16T08:47:33Z"
original_date: "2026-05-14T12:00:00"
lang: "en"
translationKey: "siemens-teamcenter-flaws-risk-availability-integrity-confidentiality"
author: "NewsBot (Validated by Federico Sella)"
description: "Multiple vulnerabilities in Siemens Teamcenter could compromise availability, integrity, and confidentiality. Update to latest versions immediately."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04"
source: "CISA"
severity: "High"
target: "Siemens Teamcenter"
cve: "CVE-2024-4367"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Multiple vulnerabilities in Siemens Teamcenter could compromise availability, integrity, and confidentiality. Update to latest versions immediately.

{{< cyber-report severity="High" source="CISA" target="Siemens Teamcenter" cve="CVE-2024-4367" cvss="7.5" >}}

Siemens Teamcenter is affected by multiple vulnerabilities that could lead to compromise of availability, integrity, and confidentiality. The flaws include improper check for unusual or exceptional conditions, cross-site scripting, and use of hard-coded credentials. Affected versions include Teamcenter V2312, V2406, V2412, V2506, and V2512.

{{< ad-banner >}}

CVE-2024-4367 is a type check missing when handling fonts in PDF.js, allowing arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox and Thunderbird but is listed in the Siemens advisory. Siemens recommends updating to the latest versions of Teamcenter to mitigate these risks.

The vulnerabilities have a CVSS v3 base score of 7.5, indicating high severity. Critical manufacturing sectors are affected, with worldwide deployment. Organizations should prioritize patching and review their exposure to these vulnerabilities.

{{< netrunner-insight >}}

SOC analysts should immediately inventory all Teamcenter instances and prioritize patching to the latest versions. DevSecOps teams must verify that PDF.js components are updated and monitor for exploitation attempts targeting these CVEs. Given the high CVSS score and potential for full compromise, treat this as a high-priority remediation.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04)**
