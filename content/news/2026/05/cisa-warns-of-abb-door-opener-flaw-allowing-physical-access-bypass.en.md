---
title: "CISA Warns of ABB Door Opener Flaw Allowing Physical Access Bypass"
date: "2026-05-30T09:11:24Z"
original_date: "2026-05-28T12:00:00"
lang: "en"
translationKey: "cisa-warns-of-abb-door-opener-flaw-allowing-physical-access-bypass"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advisory ICSA-26-148-04 details an authentication bypass vulnerability (CVE-2025-7705) in ABB Busch-Welcome 2 Wire Door Opener Actuator, enabling unauthorized building access."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04"
source: "CISA"
severity: "Medium"
target: "ABB Busch-Welcome 2 Wire Door Opener Actuator"
cve: "CVE-2025-7705"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advisory ICSA-26-148-04 details an authentication bypass vulnerability (CVE-2025-7705) in ABB Busch-Welcome 2 Wire Door Opener Actuator, enabling unauthorized building access.

{{< cyber-report severity="Medium" source="CISA" target="ABB Busch-Welcome 2 Wire Door Opener Actuator" cve="CVE-2025-7705" cvss="6.8" >}}

CISA has released advisory ICSA-26-148-04 concerning an authentication bypass vulnerability in the ABB Busch-Welcome 2 Wire Door Opener Actuator, identified as CVE-2025-7705. The flaw stems from a compatibility mode enabled by default, which allows an attacker to gain physical, unauthorized access to buildings where the affected product is installed. The vulnerability affects all versions of the Switch Actuator 4 DU and Switch actuator, door/light 4 DU.

{{< ad-banner >}}

The CVSS v3 base score for this vulnerability is 6.8, indicating a medium severity. ABB has provided remediation steps that involve toggling the mode switch on the product and performing a power reset to recalibrate the system. The product is deployed worldwide, primarily in commercial facilities, and the vendor is headquartered in Switzerland.

Organizations using the affected ABB Busch-Welcome systems should immediately apply the recommended mitigations. Given the physical security implications, this vulnerability poses a significant risk to building access control. Security teams should verify that the recalibration steps are executed correctly and monitor for any signs of exploitation.

{{< netrunner-insight >}}

This vulnerability is a stark reminder that IoT and building automation devices often ship with insecure defaults. SOC analysts should prioritize asset discovery for ABB Busch-Welcome systems and ensure the manual recalibration is applied. DevSecOps teams must advocate for secure-by-design principles, especially for devices controlling physical access.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04)**
