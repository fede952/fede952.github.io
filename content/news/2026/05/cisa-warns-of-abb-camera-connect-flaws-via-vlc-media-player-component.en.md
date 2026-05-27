---
title: "CISA Warns of ABB Camera Connect Flaws via VLC Media Player Component"
date: "2026-05-27T10:51:57Z"
original_date: "2026-05-26T12:00:00"
lang: "en"
translationKey: "cisa-warns-of-abb-camera-connect-flaws-via-vlc-media-player-component"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB Ability Camera Connect versions ≤1.5.0.14 include a vulnerable VLC media player 2.2.4 with multiple memory corruption bugs, including CVE-2024-46461, posing critical risk."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05"
source: "CISA"
severity: "Critical"
target: "ABB Ability Camera Connect"
cve: "CVE-2024-46461"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB Ability Camera Connect versions ≤1.5.0.14 include a vulnerable VLC media player 2.2.4 with multiple memory corruption bugs, including CVE-2024-46461, posing critical risk.

{{< cyber-report severity="Critical" source="CISA" target="ABB Ability Camera Connect" cve="CVE-2024-46461" cvss="9.8" >}}

CISA has released an advisory (ICSA-26-146-05) detailing multiple vulnerabilities in ABB Ability Camera Connect versions 1.5.0.14 and below. The flaws originate from an outdated third-party component, VLC media player version 2.2.4, which is bundled with the installation package. An update to version 1.5.0.15 resolves the issue by replacing the vulnerable component.

{{< ad-banner >}}

The vulnerabilities include heap-based buffer overflow, integer underflow, out-of-bounds write, uncontrolled search path element, integer overflow, off-by-one error, out-of-bounds read, double free, improper restriction of operations within memory buffers, and use-after-free. Notably, CVE-2024-46461 describes a heap-based overflow in VLC media player 3.0.20 and earlier via a maliciously crafted MMS stream, leading to denial of service.

With a CVSS v3 score of 9.8, these vulnerabilities are rated Critical. Affected critical infrastructure sectors include Chemical, Commercial Facilities, Communications, Critical Manufacturing, Energy, and Transportation Systems. The product is deployed worldwide, and exploitation could allow an attacker to compromise the system in various ways.

{{< netrunner-insight >}}

This advisory underscores the risk of inherited vulnerabilities from third-party components. SOC analysts should prioritize patching ABB Ability Camera Connect to version 1.5.0.15 and monitor for exploitation attempts targeting VLC media player flaws. DevSecOps teams must enforce strict component version control and regular scanning of bundled libraries.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05)**
