---
title: "Siemens Ruggedcom ROX Flaw Allows Root File Read via Argument Injection"
date: "2026-05-17T09:01:07Z"
original_date: "2026-05-14T12:00:00"
lang: "en"
translationKey: "siemens-ruggedcom-rox-flaw-allows-root-file-read-via-argument-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of CVE-2025-40948 affecting multiple Ruggedcom ROX devices. An authenticated remote attacker can read arbitrary files with root privileges. Update to v2.17.1 or later."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02"
source: "CISA"
severity: "Medium"
target: "Siemens Ruggedcom ROX devices"
cve: "CVE-2025-40948"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of CVE-2025-40948 affecting multiple Ruggedcom ROX devices. An authenticated remote attacker can read arbitrary files with root privileges. Update to v2.17.1 or later.

{{< cyber-report severity="Medium" source="CISA" target="Siemens Ruggedcom ROX devices" cve="CVE-2025-40948" cvss="6.8" >}}

Siemens Ruggedcom ROX series devices are affected by an improper access control vulnerability (CVE-2025-40948) that allows an authenticated remote attacker to read arbitrary files with root privileges from the underlying operating system. The flaw stems from improper validation of input in the web server's JSON-RPC interface, enabling argument injection.

{{< ad-banner >}}

The following products are vulnerable: RUGGEDCOM ROX MX5000, MX5000RE, RX1400, RX1500, RX1501, RX1510, RX1511, RX1512, RX1524, RX1536, and RX5000, all running versions prior to 2.17.1. Siemens has released updates to address the issue and recommends immediate patching.

With a CVSS v3 score of 6.8, this vulnerability is rated Medium severity. The attack vector is network-based, requires low privileges, and no user interaction. Given the critical infrastructure sectors (e.g., Critical Manufacturing) where these devices are deployed, exploitation could lead to significant information disclosure.

{{< netrunner-insight >}}

For SOC analysts: prioritize patching Ruggedcom ROX devices in your environment, especially those exposed to untrusted networks. The authenticated nature of the exploit reduces immediate risk but does not eliminate it—attackers who compromise a low-privilege account can escalate to full root file access. DevSecOps teams should review JSON-RPC endpoint hardening and consider network segmentation to limit exposure.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02)**
