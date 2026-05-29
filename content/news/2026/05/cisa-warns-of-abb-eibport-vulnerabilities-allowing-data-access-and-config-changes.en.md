---
title: "CISA Warns of ABB EIBPORT Vulnerabilities Allowing Data Access and Config Changes"
date: "2026-05-29T10:43:33Z"
original_date: "2026-05-28T12:00:00"
lang: "en"
translationKey: "cisa-warns-of-abb-eibport-vulnerabilities-allowing-data-access-and-config-changes"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB EIBPORT devices are vulnerable to cross-site scripting and session ID theft. A firmware update to version 3.9.2 is available."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03"
source: "CISA"
severity: "High"
target: "ABB EIBPORT devices"
cve: "CVE-2021-22291"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB EIBPORT devices are vulnerable to cross-site scripting and session ID theft. A firmware update to version 3.9.2 is available.

{{< cyber-report severity="High" source="CISA" target="ABB EIBPORT devices" cve="CVE-2021-22291" >}}

CISA has released an advisory (ICSA-26-148-03) detailing multiple vulnerabilities in ABB EIBPORT devices, specifically the EIBPORT V3 KNX and EIBPORT V3 KNX GSM models. The vulnerabilities, which include a cross-site scripting (XSS) flaw (CWE-79) and a session ID theft issue (CVE-2021-22291), could allow an attacker to access sensitive information stored on the device and alter its configuration.

{{< ad-banner >}}

The affected firmware versions are those prior to 3.9.2. ABB has released a firmware update to remediate these privately reported vulnerabilities. The products are deployed worldwide across critical manufacturing and information technology sectors, with the vendor headquartered in Switzerland.

While no CVSS score is provided in the advisory, the potential impact on device integrity and confidentiality warrants prompt patching. Organizations using affected ABB EIBPORT devices should apply the firmware update as soon as possible to mitigate the risk of exploitation.

{{< netrunner-insight >}}

For SOC analysts, prioritize scanning for ABB EIBPORT devices running firmware below 3.9.2 and monitor for anomalous configuration changes or session anomalies. DevSecOps teams should integrate this firmware update into their patch management pipeline, especially given the device's role in building automation and critical infrastructure.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03)**
