---
title: "ABB B&R Automation Studio Flaws Expose ICS to Remote Code Execution"
date: "2026-05-23T09:00:47Z"
original_date: "2026-05-21T12:00:00"
lang: "en"
translationKey: "abb-b-r-automation-studio-flaws-expose-ics-to-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of 25 vulnerabilities in ABB B&R Automation Studio, including critical CVSS 9.8 bugs that could enable unauthorized access and remote code execution."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03"
source: "CISA"
severity: "Critical"
target: "ABB B&R Automation Studio"
cve: "CVE-2025-6965"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of 25 vulnerabilities in ABB B&R Automation Studio, including critical CVSS 9.8 bugs that could enable unauthorized access and remote code execution.

{{< cyber-report severity="Critical" source="CISA" target="ABB B&R Automation Studio" cve="CVE-2025-6965" cvss="9.8" >}}

CISA has published an advisory detailing multiple vulnerabilities in ABB B&R Automation Studio, affecting versions prior to 6.5 and version 6.5. The advisory lists 25 CVEs, including CVE-2025-6965, CVE-2025-3277, and CVE-2023-7104, among others. These vulnerabilities stem from outdated third-party components and include issues such as heap-based buffer overflows, out-of-bounds writes, use-after-free, and improper input validation.

{{< ad-banner >}}

While ABB reports no observed exploitation during testing, the vulnerabilities could present attack vectors for unauthorized access, data exposure, or remote code execution. The most severe CVEs carry a CVSS v3 score of 9.8, indicating critical severity. Affected products are used in industrial automation and control systems, making them attractive targets for threat actors.

ABB has released an update that replaces the outdated third-party component. Organizations using B&R Automation Studio are urged to apply the update immediately. Given the critical nature of these vulnerabilities and the potential for remote exploitation, asset owners should prioritize patching and monitor for any signs of compromise.

{{< netrunner-insight >}}

For SOC analysts and DevSecOps engineers, this advisory underscores the risk of third-party dependencies in ICS software. The sheer number of CVEs (25) suggests a systemic issue with component management. Prioritize inventory of B&R Automation Studio instances and apply the vendor update. Additionally, segment ICS networks to limit exposure and implement monitoring for anomalous behavior that could indicate exploitation attempts.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03)**
