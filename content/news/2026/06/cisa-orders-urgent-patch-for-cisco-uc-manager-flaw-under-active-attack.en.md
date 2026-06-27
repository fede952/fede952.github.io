---
title: "CISA orders urgent patch for Cisco UC Manager flaw under active attack"
date: "2026-06-27T09:26:21Z"
original_date: "2026-06-26T19:43:06"
lang: "en"
translationKey: "cisa-orders-urgent-patch-for-cisco-uc-manager-flaw-under-active-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Federal agencies must patch a Cisco Unified Communications Manager vulnerability by Sunday as CISA warns of active exploitation."
original_url: "https://www.bleepingcomputer.com/news/security/cisa-sets-urgent-deadline-to-fix-cisco-flaw-exploited-in-attacks/"
source: "BleepingComputer"
severity: "High"
target: "Cisco Unified Communications Manager Server"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Federal agencies must patch a Cisco Unified Communications Manager vulnerability by Sunday as CISA warns of active exploitation.

{{< cyber-report severity="High" source="BleepingComputer" target="Cisco Unified Communications Manager Server" >}}

The U.S. Cybersecurity and Infrastructure Security Agency (CISA) has issued an urgent directive requiring federal agencies to patch a vulnerability in Cisco Unified Communications Manager Server by Sunday. The flaw is reportedly being actively exploited in attacks, though specific CVE identifiers or technical details have not been disclosed in the available information.

{{< ad-banner >}}

Cisco Unified Communications Manager is a critical component for enterprise voice and video communications, making it a high-value target for threat actors. The short remediation timeline underscores the severity of the threat and the need for rapid patching across affected systems.

Organizations outside the federal government are strongly advised to prioritize this patch as well. Given the active exploitation, delays in mitigation could lead to network compromise, data exfiltration, or further lateral movement within affected environments.

{{< netrunner-insight >}}

For SOC analysts, immediately check for any Cisco UC Manager instances in your environment and verify patch status. DevSecOps teams should treat this as a P1 incident and expedite patching, as the CISA deadline indicates active threat actor interest. Monitor for unusual SIP traffic or authentication anomalies post-patch.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/cisa-sets-urgent-deadline-to-fix-cisco-flaw-exploited-in-attacks/)**
