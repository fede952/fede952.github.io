---
title: "Subnet Solutions PowerSYSTEM Center Flaws Enable Info Leak, CRLF Injection"
date: "2026-05-13T09:40:06Z"
original_date: "2026-05-12T12:00:00"
lang: "en"
translationKey: "subnet-solutions-powersystem-center-flaws-enable-info-leak-crlf-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of multiple vulnerabilities in Subnet Solutions PowerSYSTEM Center, including info disclosure and CRLF injection, affecting versions from 2020 to 2026."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02"
source: "CISA"
severity: "High"
target: "Subnet Solutions PowerSYSTEM Center"
cve: "CVE-2026-35504"
cvss: 8.2
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of multiple vulnerabilities in Subnet Solutions PowerSYSTEM Center, including info disclosure and CRLF injection, affecting versions from 2020 to 2026.

{{< cyber-report severity="High" source="CISA" target="Subnet Solutions PowerSYSTEM Center" cve="CVE-2026-35504" cvss="8.2" >}}

CISA has released an advisory (ICSA-26-132-02) detailing multiple vulnerabilities in Subnet Solutions PowerSYSTEM Center, a platform used in critical manufacturing and energy sectors. The flaws include incorrect authorization (CVE-2026-26289) that allows authenticated users with limited permissions to export device accounts and expose sensitive information normally restricted to administrators. Additionally, CRLF injection vulnerabilities (CVE-2026-35504, CVE-2026-33570, CVE-2026-35555) could enable attackers to inject malicious headers or responses.

{{< ad-banner >}}

The affected versions span PowerSYSTEM Center 2020 (5.8.x to 5.28.x), 2024 (6.0.x to 6.1.x), and 2026 (7.0.x). The vulnerabilities carry a CVSS v3 base score of 8.2, indicating high severity. Successful exploitation could lead to information disclosure and potential session manipulation or HTTP response splitting.

Given the product's deployment in critical infrastructure worldwide, organizations should prioritize patching. Subnet Solutions has likely released updates; administrators are advised to consult the vendor's security advisories and apply the latest patches. Until then, restrict network access to the PowerSYSTEM Center and monitor for anomalous activity.

{{< netrunner-insight >}}

For SOC analysts, monitor authentication logs for unusual device account exports—this is a telltale sign of CVE-2026-26289 exploitation. DevSecOps teams should immediately inventory PowerSYSTEM Center versions and apply patches, as the CRLF injection vectors (CVE-2026-35504 et al.) could be chained with other attacks to compromise session integrity. Treat this as a high-priority remediation given the CVSS 8.2 score and critical sector exposure.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02)**
