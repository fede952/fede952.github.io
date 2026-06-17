---
title: "CISA Warns of DoS Vulnerabilities in Rockwell Automation CompactLogix Controllers"
date: "2026-06-17T11:46:16Z"
original_date: "2026-06-16T12:00:00"
lang: "en"
translationKey: "cisa-warns-of-dos-vulnerabilities-in-rockwell-automation-compactlogix-controllers"
author: "NewsBot (Validated by Federico Sella)"
description: "Multiple vulnerabilities in Rockwell Automation CompactLogix 5370 controllers could allow denial-of-service attacks. CVE-2025-11694 is among the flaws."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04"
source: "CISA"
severity: "High"
target: "Rockwell Automation CompactLogix 5370 controllers"
cve: "CVE-2025-11694"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Multiple vulnerabilities in Rockwell Automation CompactLogix 5370 controllers could allow denial-of-service attacks. CVE-2025-11694 is among the flaws.

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation CompactLogix 5370 controllers" cve="CVE-2025-11694" cvss="7.5" >}}

CISA has released an advisory (ICSA-26-167-04) detailing vulnerabilities in Rockwell Automation CompactLogix 5370 controllers (L1, L2, L3). The flaws include improper validation of integrity check values and exposure of sensitive system information, which could allow an attacker to cause a denial-of-service condition. The advisory affects versions prior to V38.011.

{{< ad-banner >}}

The most notable vulnerability, CVE-2025-11694, involves missing validation of sequence numbers and source IP addresses in the CIP protocol. An attacker can exploit exposed Connection IDs visible on the web interface to perform denial-of-service attacks, resulting in a minor fault. The CVSS v3 score for this vulnerability is 7.5.

Rockwell Automation recommends updating to version V38.011 to remediate these issues. The affected products are deployed worldwide across the Critical Manufacturing sector. Organizations should prioritize patching these controllers to mitigate potential operational disruptions.

{{< netrunner-insight >}}

For SOC analysts, monitor for unusual CIP traffic patterns or repeated connection attempts targeting CompactLogix controllers. DevSecOps engineers should ensure that the web interface is not exposed to untrusted networks and apply the firmware update to V38.011 promptly. This is a straightforward DoS vector that can be mitigated with proper network segmentation and patch management.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04)**
