---
title: "CISA Warns of Critical Buffer Overflow in Siemens RUGGEDCOM APE1808 via PAN-OS"
date: "2026-05-20T10:21:56Z"
original_date: "2026-05-19T12:00:00"
lang: "en"
translationKey: "cisa-warns-of-critical-buffer-overflow-in-siemens-ruggedcom-ape1808-via-pan-os"
author: "NewsBot (Validated by Federico Sella)"
description: "A buffer overflow in Palo Alto Networks PAN-OS Captive Portal affects Siemens RUGGEDCOM APE1808 devices. CVE-2026-0300 allows unauthenticated remote code execution with root privileges."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02"
source: "CISA"
severity: "Critical"
target: "Siemens RUGGEDCOM APE1808 devices"
cve: "CVE-2026-0300"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A buffer overflow in Palo Alto Networks PAN-OS Captive Portal affects Siemens RUGGEDCOM APE1808 devices. CVE-2026-0300 allows unauthenticated remote code execution with root privileges.

{{< cyber-report severity="Critical" source="CISA" target="Siemens RUGGEDCOM APE1808 devices" cve="CVE-2026-0300" cvss="10.0" >}}

CISA has published an advisory (ICSA-26-139-02) detailing a critical buffer overflow vulnerability in the User-ID Authentication Portal (Captive Portal) service of Palo Alto Networks PAN-OS software. This flaw, tracked as CVE-2026-0300 with a CVSS score of 10.0, allows an unauthenticated attacker to execute arbitrary code with root privileges on PA-Series and VM-Series firewalls by sending specially crafted packets.

{{< ad-banner >}}

The vulnerability affects Siemens RUGGEDCOM APE1808 devices running all versions. Siemens is preparing fix versions and recommends implementing workarounds provided in Palo Alto Networks' upstream security notifications. Until patches are available, organizations should disable the Captive Portal service if not required and restrict network access to affected devices.

Given the critical CVSS score and the potential for full system compromise, immediate action is warranted. The advisory targets the Critical Manufacturing sector, with devices deployed worldwide. Operators should prioritize applying mitigations and monitoring for any signs of exploitation.

{{< netrunner-insight >}}

This is a textbook example of supply chain risk: a third-party component (PAN-OS) introduces a critical flaw into an industrial product. SOC analysts should immediately hunt for anomalous traffic to Captive Portal ports and ensure segmentation limits exposure. DevSecOps teams must inventory all instances of RUGGEDCOM APE1808 and apply the upstream Palo Alto Networks mitigations without delay.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02)**
