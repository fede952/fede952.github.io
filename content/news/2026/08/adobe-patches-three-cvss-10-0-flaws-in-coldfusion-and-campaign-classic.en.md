---
title: "Adobe Patches Three CVSS 10.0 Flaws in ColdFusion and Campaign Classic"
date: "2026-08-13T08:18:27Z"
original_date: "2026-08-12T11:13:03"
lang: "en"
translationKey: "adobe-patches-three-cvss-10-0-flaws-in-coldfusion-and-campaign-classic"
slug: "adobe-patches-three-cvss-10-0-flaws-in-coldfusion-and-campaign-classic"
author: "NewsBot (Validated by Federico Sella)"
description: "Adobe releases critical updates for ColdFusion, Commerce, and Campaign Classic, addressing command injection and privilege escalation vulnerabilities with CVSS 10.0 severity."
original_url: "https://thehackernews.com/2026/08/adobe-patches-three-cvss-100-coldfusion.html"
source: "The Hacker News"
severity: "Critical"
target: "Adobe ColdFusion, Commerce, Campaign Classic"
cve: "CVE-2026-48362"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Adobe releases critical updates for ColdFusion, Commerce, and Campaign Classic, addressing command injection and privilege escalation vulnerabilities with CVSS 10.0 severity.

{{< cyber-report severity="Critical" source="The Hacker News" target="Adobe ColdFusion, Commerce, Campaign Classic" cve="CVE-2026-48362" cvss="10.0" >}}

Adobe has shipped urgent security updates to address multiple critical vulnerabilities in ColdFusion, Commerce, and Campaign Classic. The most severe of these is CVE-2026-48362, a CVSS 10.0-rated operating system command injection vulnerability in ColdFusion that could allow an attacker to execute arbitrary code on the underlying system.

{{< ad-banner >}}

In addition to the command injection flaw, the updates address other critical issues that could lead to privilege escalation. Successful exploitation of these vulnerabilities could give attackers full control over affected servers, potentially leading to data breaches, lateral movement, or further compromise of the infrastructure.

Given the maximum CVSS score and the critical nature of these products in enterprise environments, immediate patching is strongly recommended. Organizations should also review their security monitoring for indicators of compromise related to these vulnerabilities.

{{< netrunner-insight >}}

With a CVSS 10.0 rating, these are as severe as it gets—treat them like an active exploit scenario. Prioritize patching ColdFusion and Campaign Classic servers immediately, and check for any signs of post-exploitation activity. Also, consider isolating these services from the internet if possible, and review logs for unusual command execution patterns.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/adobe-patches-three-cvss-100-coldfusion.html)**
