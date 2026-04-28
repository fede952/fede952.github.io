---
title: "CISA Warns of FIRESTARTER Backdoor Targeting Cisco Firepower Devices"
date: "2026-04-23T12:00:00"
lang: "en"
translationKey: "cisa-warns-of-firestarter-backdoor-targeting-cisco-firepower-devices"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA and NCSC alert on APT actors using FIRESTARTER backdoor for persistence on Cisco ASA/FTD devices. Urgent response actions outlined."
original_url: "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"
source: "CISA"
severity: "High"
target: "Cisco Firepower and Secure Firewall devices"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA and NCSC alert on APT actors using FIRESTARTER backdoor for persistence on Cisco ASA/FTD devices. Urgent response actions outlined.

{{< cyber-report severity="High" source="CISA" target="Cisco Firepower and Secure Firewall devices" >}}

CISA and the UK NCSC have released a Malware Analysis Report on the FIRESTARTER backdoor, which is being used by advanced persistent threat (APT) actors to maintain persistence on publicly accessible Cisco Firepower and Secure Firewall devices running ASA or FTD software. The analysis is based on a sample obtained from a forensic investigation, and CISA has confirmed successful in-the-wild implants on Cisco Firepower devices with ASA software.

{{< ad-banner >}}

The release aligns with CISA's Emergency Directive 25-03, urging U.S. FCEB agencies to collect and submit core dumps to CISA's Malware Next Generation platform and immediately report submissions via the 24/7 Operations Center. Organizations are advised to take no additional action until CISA provides next steps.

While the malware is relevant for both Cisco Firepower and Secure Firewall devices, CISA has only observed successful implants on Firepower devices running ASA. The report emphasizes the need for vigilance and proactive hunting for indicators of compromise.

{{< netrunner-insight >}}

SOC analysts should prioritize collecting core dumps from Cisco ASA/FTD devices and submitting them to CISA for analysis. DevSecOps teams must ensure that Cisco devices are patched and configured according to best practices, and monitor for unusual persistence mechanisms. This backdoor highlights the criticality of securing network edge devices against APT-level threats.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/analysis-reports/ar26-113a)**
