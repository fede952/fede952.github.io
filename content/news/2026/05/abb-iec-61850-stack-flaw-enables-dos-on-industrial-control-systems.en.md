---
title: "ABB IEC 61850 Stack Flaw Enables DoS on Industrial Control Systems"
date: "2026-05-01T09:03:14Z"
original_date: "2026-04-30T12:00:00"
lang: "en"
translationKey: "abb-iec-61850-stack-flaw-enables-dos-on-industrial-control-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of a privately reported vulnerability in ABB's IEC 61850 MMS implementation affecting System 800xA and Symphony Plus products, leading to device faults and denial-of-service."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01"
source: "CISA"
severity: "High"
target: "ABB System 800xA, Symphony Plus IEC 61850"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of a privately reported vulnerability in ABB's IEC 61850 MMS implementation affecting System 800xA and Symphony Plus products, leading to device faults and denial-of-service.

{{< cyber-report severity="High" source="CISA" target="ABB System 800xA, Symphony Plus IEC 61850" >}}

CISA has issued an advisory (ICSA-26-120-01) regarding a vulnerability in ABB's implementation of the IEC 61850 communication stack for MMS client applications. The flaw affects multiple products in the System 800xA and Symphony Plus lines, including AC800M CI868, Symphony Plus SD Series CI850, PM 877, and S+ Operations. Exploitation requires prior access to the site's IEC 61850 network.

{{< ad-banner >}}

Successful exploitation causes a device fault on PM 877, CI850, and CI868 modules, necessitating a manual restart. For S+ Operations nodes, the attack crashes the IEC 61850 communication driver, leading to a denial-of-service condition if repeated. However, the overall node availability and functionality remain unaffected, and GOOSE protocol communication is not impacted. The System 800xA IEC61850 Connect is also not vulnerable.

Affected firmware versions span multiple branches, including S+ Operations up to 6.2.0006.0 and various PM 877 releases. No CVE identifier or CVSS score was provided in the advisory. Organizations using these products should review the advisory and apply mitigations, such as network segmentation and access controls, to limit exposure to the IEC 61850 network.

{{< netrunner-insight >}}

This vulnerability underscores the importance of network segmentation in OT environments. Since exploitation requires access to the IEC 61850 network, isolating that network from corporate IT and the internet is critical. SOC analysts should monitor for anomalous IEC 61850 traffic, while DevSecOps engineers should prioritize patching and consider implementing intrusion detection for MMS protocol anomalies.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01)**
