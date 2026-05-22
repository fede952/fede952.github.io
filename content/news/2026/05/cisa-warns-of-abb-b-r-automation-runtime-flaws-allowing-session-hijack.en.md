---
title: "CISA Warns of ABB B&R Automation Runtime Flaws Allowing Session Hijack"
date: "2026-05-22T10:20:32Z"
original_date: "2026-05-21T12:00:00"
lang: "en"
translationKey: "cisa-warns-of-abb-b-r-automation-runtime-flaws-allowing-session-hijack"
author: "NewsBot (Validated by Federico Sella)"
description: "Multiple vulnerabilities in ABB B&R Automation Runtime before 6.4 could let attackers hijack sessions or execute code. CISA advisory ICSA-26-141-04 details fixes."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04"
source: "CISA"
severity: "Medium"
target: "ABB B&R Automation Runtime"
cve: "CVE-2025-3449"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Multiple vulnerabilities in ABB B&R Automation Runtime before 6.4 could let attackers hijack sessions or execute code. CISA advisory ICSA-26-141-04 details fixes.

{{< cyber-report severity="Medium" source="CISA" target="ABB B&R Automation Runtime" cve="CVE-2025-3449" cvss="6.1" >}}

CISA has released advisory ICSA-26-141-04 detailing multiple vulnerabilities in ABB B&R Automation Runtime, a software platform used in industrial automation. The flaws, identified by B&R's internal security analysis, affect versions prior to 6.4 and include CVE-2025-3449 (predictable session identifiers), CVE-2025-3448 (cross-site scripting), and CVE-2025-11498 (improper neutralization of formula elements in CSV files). An unauthenticated attacker could exploit these to hijack remote sessions or execute code in the context of a user's browser.

{{< ad-banner >}}

The most severe vulnerability, CVE-2025-3449, resides in the System Diagnostic Manager (SDM) component and carries a CVSS v3 score of 6.1. It allows an unauthenticated network-based attacker to take over already established sessions due to generation of predictable numbers or identifiers. The SDM is disabled by default in Automation Runtime 6, reducing exposure, but organizations should verify it remains off unless explicitly needed.

ABB has released Automation Runtime version 6.4 to remediate these issues. Given the product's deployment across the energy sector worldwide, CISA urges operators to apply the update promptly. The advisory notes that successful exploitation could lead to remote code execution or session takeover, posing significant risk to industrial control environments.

{{< netrunner-insight >}}

For SOC analysts: prioritize patching Automation Runtime instances, especially those with SDM enabled. The predictable session ID flaw (CVE-2025-3449) is trivially exploitable over the network. DevSecOps teams should ensure SDM remains disabled in production and validate that no exposed instances are reachable from untrusted networks. Monitor for anomalous session activity as a detection signal.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04)**
