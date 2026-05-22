---
title: "ABB Terra AC Wallbox Vulnerabilities Allow Remote Code Execution"
date: "2026-05-22T10:24:17Z"
original_date: "2026-05-21T12:00:00"
lang: "en"
translationKey: "abb-terra-ac-wallbox-vulnerabilities-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of heap and stack buffer overflows in ABB Terra AC Wallbox (JP) ≤1.8.33; update to 1.8.36 to mitigate CVE-2025-10504, CVE-2025-12142, CVE-2025-12143."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05"
source: "CISA"
severity: "Medium"
target: "ABB Terra AC Wallbox (JP)"
cve: "CVE-2025-10504"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of heap and stack buffer overflows in ABB Terra AC Wallbox (JP) ≤1.8.33; update to 1.8.36 to mitigate CVE-2025-10504, CVE-2025-12142, CVE-2025-12143.

{{< cyber-report severity="Medium" source="CISA" target="ABB Terra AC Wallbox (JP)" cve="CVE-2025-10504" cvss="6.1" >}}

ABB has disclosed multiple vulnerabilities affecting its Terra AC Wallbox (JP) product line, specifically versions up to and including 1.8.33. The flaws include a heap-based buffer overflow (CVE-2025-10504), a buffer copy without checking input size (CVE-2025-12142), and a stack-based buffer overflow (CVE-2025-12143). Successful exploitation could allow an attacker to corrupt heap memory, potentially leading to remote control of the device and unauthorized writes to flash memory, thereby altering firmware behavior.

{{< ad-banner >}}

The vulnerabilities are rated with a CVSS v3 base score of 6.1, indicating medium severity. ABB has released firmware version 1.8.36 to address these issues. The products are deployed worldwide in the energy sector, and the vendor recommends applying the update at the earliest convenience.

While no active exploitation has been reported, the potential for remote code execution and firmware manipulation makes these vulnerabilities critical for operators of EV charging infrastructure. Organizations should prioritize patching affected devices, especially those exposed to untrusted networks.

{{< netrunner-insight >}}

For SOC analysts, monitor for anomalous traffic to Terra AC Wallbox devices, especially unexpected write operations to flash memory. DevSecOps engineers should enforce strict input validation in any custom protocols communicating with the charger and ensure firmware updates are applied promptly. Given the CVSS score of 6.1, treat these as medium priority but with high potential impact due to the device's role in critical energy infrastructure.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05)**
