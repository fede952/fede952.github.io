---
title: "CISA Warns of Critical Auth Bypass in Rockwell FactoryTalk Analytics PavilionX"
date: "2026-06-18T11:06:01Z"
original_date: "2026-06-16T12:00:00"
lang: "en"
translationKey: "cisa-warns-of-critical-auth-bypass-in-rockwell-factorytalk-analytics-pavilionx"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerts on CVE-2025-14272 affecting Rockwell Automation FactoryTalk Analytics PavilionX <7.01, allowing unauthorized privileged operations in critical manufacturing environments."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01"
source: "CISA"
severity: "High"
target: "Rockwell FactoryTalk Analytics PavilionX"
cve: "CVE-2025-14272"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerts on CVE-2025-14272 affecting Rockwell Automation FactoryTalk Analytics PavilionX <7.01, allowing unauthorized privileged operations in critical manufacturing environments.

{{< cyber-report severity="High" source="CISA" target="Rockwell FactoryTalk Analytics PavilionX" cve="CVE-2025-14272" >}}

CISA has published an advisory (ICSA-26-167-01) regarding a missing authorization vulnerability in Rockwell Automation FactoryTalk Analytics PavilionX. The flaw, tracked as CVE-2025-14272, affects versions prior to 7.01 and allows an unauthorized attacker to execute privileged operations such as user and role management.

{{< ad-banner >}}

The vulnerability stems from improper authorization enforcement in API endpoints. Successful exploitation could lead to full administrative control over the affected system. Rockwell Automation has released version 7.01 to remediate the issue, and users are urged to upgrade immediately.

Given the deployment of this product across critical manufacturing sectors worldwide, the risk of operational disruption or data compromise is significant. Organizations should prioritize patching and review access controls to mitigate potential exploitation.

{{< netrunner-insight >}}

This is a classic authorization bypass that should be treated as a high-priority patch. SOC analysts should monitor for anomalous API calls or privilege escalations in PavilionX environments. DevSecOps teams must ensure that version 7.01 is deployed and that network segmentation limits exposure of these endpoints.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01)**
