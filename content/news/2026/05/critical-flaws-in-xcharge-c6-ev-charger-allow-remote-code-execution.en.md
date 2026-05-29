---
title: "Critical Flaws in XCharge C6 EV Charger Allow Remote Code Execution"
date: "2026-05-29T10:39:44Z"
original_date: "2026-05-28T12:00:00"
lang: "en"
translationKey: "critical-flaws-in-xcharge-c6-ev-charger-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of unauthenticated vulnerabilities in XCharge C6 EV charging controllers, including CVE-2026-9037, with a CVSS score of 9.8."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08"
source: "CISA"
severity: "Critical"
target: "XCharge C6 EV charging controllers"
cve: "CVE-2026-9037"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of unauthenticated vulnerabilities in XCharge C6 EV charging controllers, including CVE-2026-9037, with a CVSS score of 9.8.

{{< cyber-report severity="Critical" source="CISA" target="XCharge C6 EV charging controllers" cve="CVE-2026-9037" cvss="9.8" >}}

CISA has released an advisory (ICSA-26-148-08) detailing multiple critical vulnerabilities in XCharge C6 electric vehicle charging controllers. The flaws include a download of code without integrity check (CWE-494), stack-based buffer overflow, and initialization of a resource with an insecure default. Successful exploitation could allow an attacker to gain administrator rights or execute arbitrary code on the device.

{{< ad-banner >}}

The most severe vulnerability, CVE-2026-9037, involves a firmware update mechanism that fails to validate the authenticity of firmware packages. Without cryptographic signature verification, an attacker who can interfere with or impersonate the management channel could install unauthorized firmware, leading to high-privilege code execution. The CVSS v3 score for this vulnerability is 9.8, indicating critical severity.

XCharge has deployed a firmware update for all affected chargers as of May 22, 2026. Users are advised to ensure their devices are updated and to contact XCharge support if needed. The affected product is widely deployed in the transportation systems sector across multiple countries.

{{< netrunner-insight >}}

For SOC analysts, prioritize monitoring management interfaces of XCharge C6 chargers for unauthorized access or anomalous firmware update requests. DevSecOps teams should enforce network segmentation and apply the vendor patch immediately, as the lack of integrity checks makes these devices a prime target for supply chain attacks.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08)**
