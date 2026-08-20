---
title: "CISA Adds 4 Critical Flaws to KEV: macOS, SharePoint, vCenter, IKE"
date: "2026-08-20T07:34:38Z"
original_date: "2026-08-19T11:01:48"
lang: "en"
translationKey: "cisa-adds-4-critical-flaws-to-kev-macos-sharepoint-vcenter-ike"
slug: "cisa-adds-4-critical-flaws-to-kev-macos-sharepoint-vcenter-ike"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA flags four critical vulnerabilities in macOS, SharePoint, vCenter, and Microsoft IKE as actively exploited, urging immediate patching."
original_url: "https://thehackernews.com/2026/08/critical-macos-sharepoint-vcenter-and.html"
source: "The Hacker News"
severity: "Critical"
target: "Apple macOS"
cve: "CVE-2026-65400"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA flags four critical vulnerabilities in macOS, SharePoint, vCenter, and Microsoft IKE as actively exploited, urging immediate patching.

{{< cyber-report severity="Critical" source="The Hacker News" target="Apple macOS" cve="CVE-2026-65400" cvss="9.8" kev="true" >}}

The U.S. Cybersecurity and Infrastructure Security Agency (CISA) has added four critical vulnerabilities to its Known Exploited Vulnerabilities (KEV) catalog, indicating active exploitation in the wild. The flaws affect Apple macOS, Microsoft SharePoint, VMware vCenter, and Microsoft's IKE protocol, posing significant risks to enterprise environments.

{{< ad-banner >}}

Among the listed vulnerabilities is CVE-2026-65400, an improper authentication issue in Apple macOS with a CVSS score of 9.8, which could allow attackers to bypass authentication mechanisms. While specific technical details for the other three flaws were not disclosed in the summary, their inclusion in the KEV catalog underscores the urgency for organizations to prioritize patching and mitigation.

CISA's KEV catalog serves as a critical resource for federal agencies and private sector entities to identify and remediate vulnerabilities that are actively exploited. Security teams should immediately assess their exposure to these flaws and apply vendor-provided patches or workarounds to reduce the risk of compromise.

{{< netrunner-insight >}}

For SOC analysts, the addition of these CVEs to CISA's KEV catalog is a clear signal to prioritize detection and response efforts. Ensure your vulnerability management program includes immediate patching for these specific products, and monitor network traffic for indicators of exploitation. DevSecOps teams should integrate KEV data into their CI/CD pipelines to block deployments that rely on vulnerable components.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/critical-macos-sharepoint-vcenter-and.html)**
