---
title: "CISA Adds Langflow RCE, Tomcat, N-central Flaws to KEV Catalog"
date: "2026-08-05T09:30:51Z"
original_date: "2026-08-05T07:40:39"
lang: "en"
translationKey: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
slug: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA flags three actively exploited vulnerabilities including Langflow RCE (CVE-2026-9198) with CVSS 9.8, urging immediate patching."
original_url: "https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html"
source: "The Hacker News"
severity: "Critical"
target: "Langflow, Apache Tomcat, N-central"
cve: "CVE-2026-9198"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA flags three actively exploited vulnerabilities including Langflow RCE (CVE-2026-9198) with CVSS 9.8, urging immediate patching.

{{< cyber-report severity="Critical" source="The Hacker News" target="Langflow, Apache Tomcat, N-central" cve="CVE-2026-9198" cvss="9.8" kev="true" >}}

The U.S. Cybersecurity and Infrastructure Security Agency (CISA) has added three vulnerabilities to its Known Exploited Vulnerabilities (KEV) catalog, citing evidence of active exploitation. Among them is CVE-2026-9198, a critical code injection flaw in Langflow that allows unauthenticated attackers to achieve full remote code execution. The vulnerability carries a CVSS score of 9.8, indicating severe risk.

{{< ad-banner >}}

The other two flaws affect Apache Tomcat and N-central, though specific details are not provided in the summary. CISA's KEV catalog is a prioritized list of vulnerabilities known to be exploited, and federal agencies are required to remediate these within specified timelines. Organizations are urged to review the catalog and apply patches immediately.

The inclusion of these vulnerabilities underscores the importance of timely patch management and threat intelligence. Security teams should monitor for indicators of compromise related to these CVEs and ensure that their assets are not exposed to known attack vectors.

{{< netrunner-insight >}}

For SOC analysts, prioritize monitoring for exploitation attempts against Langflow, Tomcat, and N-central, as these are now confirmed active targets. DevSecOps should expedite patching, especially for internet-facing instances, and consider implementing additional detection rules for post-exploitation activity. Given the critical CVSS score, treat CVE-2026-9198 as a top-tier risk and validate that no unauthorized access has occurred.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html)**
