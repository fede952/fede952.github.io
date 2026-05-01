---
title: "CISA Warns of ABB PCM600 Path Traversal Flaw Leading to RCE"
date: "2026-05-01T08:59:15Z"
original_date: "2026-04-30T12:00:00"
lang: "en"
translationKey: "cisa-warns-of-abb-pcm600-path-traversal-flaw-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB PCM600 versions 1.5 to 2.13 are vulnerable to a path traversal flaw (CVE-2018-1002208) that could allow arbitrary code execution. Update to version 2.14."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02"
source: "CISA"
severity: "Medium"
target: "ABB PCM600"
cve: "CVE-2018-1002208"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB PCM600 versions 1.5 to 2.13 are vulnerable to a path traversal flaw (CVE-2018-1002208) that could allow arbitrary code execution. Update to version 2.14.

{{< cyber-report severity="Medium" source="CISA" target="ABB PCM600" cve="CVE-2018-1002208" >}}

CISA has released an advisory (ICSA-26-120-02) detailing a vulnerability in ABB PCM600, a protection and control IED manager. The flaw, identified as CVE-2018-1002208, exists in the SharpZip.dll library and involves improper limitation of a pathname to a restricted directory (path traversal). Successful exploitation could allow an attacker to send specially crafted messages to the system node, resulting in arbitrary code execution.

{{< ad-banner >}}

The affected product versions are PCM600 from 1.5 up to and including 2.13. ABB has released version 2.14 to remediate the issue. However, note that RE_630 protection relays are not compatible with PCM600 2.14, so users of earlier versions with RE_630 must rely on system-level defenses as outlined in ABB's General Security Recommendations.

The advisory highlights that the product is deployed worldwide across the Critical Manufacturing sector. While no CVSS score is provided in the advisory, the vulnerability's potential for code execution warrants prompt patching where possible. Organizations should prioritize updating to PCM600 2.14 and implement network segmentation and access controls for systems that cannot be immediately updated.

{{< netrunner-insight >}}

This path traversal vulnerability in ABB PCM600 is a reminder that legacy dependencies like SharpZip.dll can introduce risk. For SOC analysts, monitor for anomalous network traffic to PCM600 nodes, especially crafted messages that could indicate exploitation attempts. DevSecOps engineers should inventory all instances of PCM600 and plan upgrades to version 2.14, while ensuring compatibility with RE_630 relays is addressed through compensating controls.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02)**
