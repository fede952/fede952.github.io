---
title: "ABB Zenon Remote Transport Flaw Allows Unauthenticated Reboot"
date: "2026-05-28T10:50:49Z"
original_date: "2026-05-26T12:00:00"
lang: "en"
translationKey: "abb-zenon-remote-transport-flaw-allows-unauthenticated-reboot"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of CVE-2025-8754 in ABB Ability Zenon, enabling unauthorized system reboots via Remote Transport Service. No active exploitation reported."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03"
source: "CISA"
severity: "High"
target: "ABB Ability Zenon systems"
cve: "CVE-2025-8754"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of CVE-2025-8754 in ABB Ability Zenon, enabling unauthorized system reboots via Remote Transport Service. No active exploitation reported.

{{< cyber-report severity="High" source="CISA" target="ABB Ability Zenon systems" cve="CVE-2025-8754" cvss="7.5" >}}

CISA has published an advisory (ICSA-26-146-03) detailing a missing authentication vulnerability in ABB Ability Zenon's Remote Transport Service. The flaw, tracked as CVE-2025-8754 with a CVSS score of 7.5, allows an attacker to trigger a system reboot without proper credentials. The affected versions range from 7.50 to 14.

{{< ad-banner >}}

Exploitation requires prior network access, as the attacker must already be on the same network as the target Zenon system. ABB notes that in default configurations, the zensyssrv.exe service starts automatically, but users must configure a password to use the Remote Transport Service. At the time of writing, there is no evidence of active exploitation in the wild.

The advisory highlights the broad deployment of ABB Ability Zenon across critical infrastructure sectors including Chemical, Energy, Healthcare, and Water and Wastewater systems worldwide. Organizations using affected versions should immediately apply mitigations or updates provided by ABB to prevent potential denial-of-service attacks.

{{< netrunner-insight >}}

For SOC analysts: prioritize network segmentation to limit exposure of Zenon systems, and ensure Remote Transport Service passwords are configured and strong. DevSecOps teams should verify that the zensyssrv.exe service is not exposed to untrusted networks, and apply vendor patches as soon as they become available. Given the CVSS 7.5 and critical infrastructure impact, treat this as a high-priority finding even without active exploitation.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03)**
