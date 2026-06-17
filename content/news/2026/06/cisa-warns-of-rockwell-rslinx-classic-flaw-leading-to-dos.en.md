---
title: "CISA Warns of Rockwell RSLinx Classic Flaw Leading to DoS"
date: "2026-06-17T11:42:55Z"
original_date: "2026-06-16T12:00:00"
lang: "en"
translationKey: "cisa-warns-of-rockwell-rslinx-classic-flaw-leading-to-dos"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advisory highlights CVE-2020-13573, a stack-based buffer overflow in Rockwell Automation RSLinx Classic ≤4.50.00, risking denial of service and remote code execution."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02"
source: "CISA"
severity: "High"
target: "Rockwell Automation RSLinx Classic"
cve: "CVE-2020-13573"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advisory highlights CVE-2020-13573, a stack-based buffer overflow in Rockwell Automation RSLinx Classic ≤4.50.00, risking denial of service and remote code execution.

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation RSLinx Classic" cve="CVE-2020-13573" cvss="7.5" >}}

CISA has released an advisory (ICSA-26-167-02) concerning a vulnerability in Rockwell Automation RSLinx Classic, a widely used industrial communication software. The flaw, identified as CVE-2020-13573, is a stack-based buffer overflow that can be exploited remotely to execute arbitrary code or cause a denial of service, leaving the application unresponsive and unable to recover automatically.

{{< ad-banner >}}

The affected versions include RSLinx Classic up to and including version 4.50.00. The vulnerability carries a CVSS v3 score of 7.5, indicating high severity. Rockwell Automation recommends upgrading to version 4.60.00 or later, or applying patch BF31213 for customers unable to upgrade immediately. The advisory also references CWE-125 (Out-of-bounds Read) as the underlying weakness.

Given the critical infrastructure sectors involved—Critical Manufacturing, Energy, Food and Agriculture, and Water and Wastewater—and the global deployment of the product, timely patching is essential. Organizations should prioritize this update to mitigate the risk of exploitation, especially in environments where RSLinx Classic is exposed to untrusted networks.

{{< netrunner-insight >}}

For SOC analysts, monitor for unusual crashes or unresponsiveness in RSLinx Classic processes, as these may indicate exploitation attempts. DevSecOps teams should immediately plan the upgrade to version 4.60.00 or apply patch BF31213, and ensure that RSLinx instances are not directly accessible from the internet. Given the CVSS score and the potential for remote code execution, treat this as a high-priority remediation item.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02)**
