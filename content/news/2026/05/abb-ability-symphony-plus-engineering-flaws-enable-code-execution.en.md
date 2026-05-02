---
title: "ABB Ability Symphony Plus Engineering Flaws Enable Code Execution"
date: "2026-05-02T08:20:38Z"
original_date: "2026-04-30T12:00:00"
lang: "en"
translationKey: "abb-ability-symphony-plus-engineering-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of vulnerabilities in ABB Ability Symphony Plus Engineering due to outdated PostgreSQL, allowing arbitrary code execution on affected systems."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06"
source: "CISA"
severity: "High"
target: "ABB Ability Symphony Plus Engineering"
cve: "CVE-2023-5869"
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of vulnerabilities in ABB Ability Symphony Plus Engineering due to outdated PostgreSQL, allowing arbitrary code execution on affected systems.

{{< cyber-report severity="High" source="CISA" target="ABB Ability Symphony Plus Engineering" cve="CVE-2023-5869" cvss="8.8" >}}

CISA has released an advisory (ICSA-26-120-06) detailing multiple vulnerabilities in ABB Ability Symphony Plus Engineering, stemming from the use of PostgreSQL version 13.11 and earlier. The flaws include integer overflow, SQL injection, TOCTOU race condition, and privilege dropping errors, which could allow an authenticated attacker to execute arbitrary code on the system.

{{< ad-banner >}}

Affected versions span from Ability Symphony Plus 2.2 through 2.4 SP2 RU1. The vulnerabilities are particularly concerning given the product's deployment across critical infrastructure sectors such as Chemical, Critical Manufacturing, Energy, and Water and Wastewater worldwide.

The most notable vulnerability, CVE-2023-5869, carries a CVSS score of 8.8 and involves an integer overflow that can be triggered by crafted data from an authenticated PostgreSQL user. Successful exploitation could lead to full system compromise, emphasizing the need for immediate patching.

{{< netrunner-insight >}}

This advisory underscores the risk of outdated dependencies in OT environments. SOC analysts should prioritize asset discovery for ABB Symphony Plus instances and ensure PostgreSQL is updated beyond 13.11. DevSecOps teams must integrate dependency scanning into CI/CD pipelines for industrial control systems to catch such inherited vulnerabilities early.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06)**
