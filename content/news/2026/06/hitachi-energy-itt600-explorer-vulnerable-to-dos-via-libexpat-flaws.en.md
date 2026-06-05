---
title: "Hitachi Energy ITT600 Explorer Vulnerable to DoS via libexpat Flaws"
date: "2026-06-05T10:44:09Z"
original_date: "2026-06-04T12:00:00"
lang: "en"
translationKey: "hitachi-energy-itt600-explorer-vulnerable-to-dos-via-libexpat-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of two vulnerabilities in Hitachi Energy ITT600 Explorer that could allow denial-of-service attacks. Affects versions prior to 2.1 SP6."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02"
source: "CISA"
severity: "High"
target: "Hitachi Energy ITT600 Explorer"
cve: "CVE-2024-8176"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of two vulnerabilities in Hitachi Energy ITT600 Explorer that could allow denial-of-service attacks. Affects versions prior to 2.1 SP6.

{{< cyber-report severity="High" source="CISA" target="Hitachi Energy ITT600 Explorer" cve="CVE-2024-8176" cvss="7.5" >}}

Hitachi Energy has disclosed vulnerabilities in its ITT600 Explorer product, specifically affecting versions prior to 2.1 SP6. The flaws, identified as CVE-2024-8176 and CVE-2025-59375, involve uncontrolled recursion and allocation of resources without limits or throttling. These issues can be exploited to cause a denial-of-service (DoS) condition.

{{< ad-banner >}}

The vulnerabilities reside in the libexpat library used by the IEC61850 functionality. An attacker with local access could send a crafted IEC61850 message to trigger a stack overflow, potentially leading to memory corruption in addition to DoS. Importantly, only the ITT600 Explorer product is affected; IEC 61850 system endpoints remain unaffected.

CISA recommends immediate action to apply mitigations or updates. The product is deployed worldwide across the energy sector, and exploitation could disrupt critical infrastructure operations. Organizations using affected versions should prioritize patching and review the advisory for detailed remediation steps.

{{< netrunner-insight >}}

For SOC analysts, monitor for unusual IEC61850 traffic patterns that may indicate exploitation attempts. DevSecOps teams should prioritize updating ITT600 Explorer to version 2.1 SP6 or later, and consider network segmentation to limit local access to the tool. Given the CVSS score of 7.5 and potential for memory corruption, treat this as a high-priority patch.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02)**
