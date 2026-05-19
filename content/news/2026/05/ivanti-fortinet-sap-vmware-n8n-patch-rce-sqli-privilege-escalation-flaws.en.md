---
title: "Ivanti, Fortinet, SAP, VMware, n8n Patch RCE, SQLi, Privilege Escalation Flaws"
date: "2026-05-19T10:36:29Z"
original_date: "2026-05-18T10:54:05"
lang: "en"
translationKey: "ivanti-fortinet-sap-vmware-n8n-patch-rce-sqli-privilege-escalation-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "Multiple vendors release security fixes for critical vulnerabilities including Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) that could lead to information disclosure or client-side attacks."
original_url: "https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html"
source: "The Hacker News"
severity: "Critical"
target: "Ivanti Xtraction"
cve: "CVE-2026-8043"
cvss: 9.6
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Multiple vendors release security fixes for critical vulnerabilities including Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) that could lead to information disclosure or client-side attacks.

{{< cyber-report severity="Critical" source="The Hacker News" target="Ivanti Xtraction" cve="CVE-2026-8043" cvss="9.6" >}}

Ivanti, Fortinet, n8n, SAP, and VMware have released security patches addressing multiple vulnerabilities that could be exploited for authentication bypass and arbitrary code execution. The most critical flaw is CVE-2026-8043 in Ivanti Xtraction, with a CVSS score of 9.6, which allows external control of a file name leading to information disclosure or client-side attacks.

{{< ad-banner >}}

Other vendors also addressed high-severity issues including SQL injection and privilege escalation vulnerabilities. Organizations are urged to prioritize patching these flaws, especially those exposed to the internet, as they could be chained for full system compromise.

While no active exploitation has been reported yet, the broad attack surface and high CVSS scores warrant immediate attention from security teams. Regular vulnerability scanning and patch management are critical to mitigate risks.

{{< netrunner-insight >}}

SOC analysts should prioritize the Ivanti Xtraction CVE-2026-8043 patch due to its critical CVSS score and potential for client-side attacks. DevSecOps teams must verify that all affected systems are updated and monitor for any signs of exploitation, as external control of file names can lead to data exfiltration or lateral movement.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html)**
