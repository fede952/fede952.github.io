---
title: "CISA Warns of ABB AWIN Gateway Flaws Allowing Reboot, Data Leak"
date: "2026-05-01T08:55:30Z"
original_date: "2026-04-30T12:00:00"
lang: "en"
translationKey: "cisa-warns-of-abb-awin-gateway-flaws-allowing-reboot-data-leak"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB AWIN gateways have vulnerabilities that let attackers reboot devices or extract system config. CISA advisory ICSA-26-120-05 details CVE-2025-13777 and fixes."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05"
source: "CISA"
severity: "High"
target: "ABB AWIN Gateways"
cve: "CVE-2025-13777"
cvss: 8.3
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB AWIN gateways have vulnerabilities that let attackers reboot devices or extract system config. CISA advisory ICSA-26-120-05 details CVE-2025-13777 and fixes.

{{< cyber-report severity="High" source="CISA" target="ABB AWIN Gateways" cve="CVE-2025-13777" cvss="8.3" >}}

CISA has released advisory ICSA-26-120-05 detailing multiple vulnerabilities in ABB AWIN gateways. The flaws, which include authentication bypass via capture-replay and missing authentication for critical functions, could allow an unauthenticated attacker to remotely reboot the device or query sensitive system configuration data. The vulnerabilities affect AWIN firmware versions 2.0-0, 2.0-1, 1.2-0, and 1.2-1 running on GW100 rev.2 and GW120 hardware.

{{< ad-banner >}}

The most severe issue, tracked as CVE-2025-13777, enables an unauthenticated query to reveal system configuration, including sensitive details. The advisory assigns a CVSS v3 base score of 8.3, indicating high severity. ABB has released firmware version 2.1-0 for the GW100 rev.2 to remediate these vulnerabilities. Organizations using affected gateways are urged to apply the update immediately.

The vulnerabilities impact critical manufacturing sector assets deployed worldwide. Given the potential for remote exploitation without authentication, these flaws pose a significant risk to operational technology environments. CISA recommends that users review the full advisory and implement mitigations, including network segmentation and restricting access to affected devices.

{{< netrunner-insight >}}

For SOC analysts: monitor for unauthorized reboots or unusual queries to ABB gateways; these are low-noise indicators of exploitation. DevSecOps teams should prioritize patching to firmware 2.1-0 and enforce strict network access controls, as the vulnerabilities require no authentication and can be exploited remotely.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05)**
