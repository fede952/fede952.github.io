---
title: "Windows BitLocker zero-day bypass PoC released: YellowKey and GreenPlasma"
date: "2026-05-14T09:30:15Z"
original_date: "2026-05-13T16:37:49"
lang: "en"
translationKey: "windows-bitlocker-zero-day-bypass-poc-released-yellowkey-and-greenplasma"
author: "NewsBot (Validated by Federico Sella)"
description: "Proof-of-concept exploits for two unpatched Windows vulnerabilities—YellowKey (BitLocker bypass) and GreenPlasma (privilege escalation)—have been published, posing risks to encrypted drives."
original_url: "https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/"
source: "BleepingComputer"
severity: "High"
target: "Windows BitLocker protected drives"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Proof-of-concept exploits for two unpatched Windows vulnerabilities—YellowKey (BitLocker bypass) and GreenPlasma (privilege escalation)—have been published, posing risks to encrypted drives.

{{< cyber-report severity="High" source="BleepingComputer" target="Windows BitLocker protected drives" >}}

A cybersecurity researcher has released proof-of-concept (PoC) exploits for two unpatched Microsoft Windows vulnerabilities, dubbed YellowKey and GreenPlasma. YellowKey is a BitLocker bypass that allows attackers to access data on protected drives without proper authentication, while GreenPlasma is a privilege-escalation flaw that could enable an attacker to gain elevated permissions on a compromised system.

{{< ad-banner >}}

The publication of these PoCs increases the risk of exploitation, as threat actors can now weaponize the techniques. Organizations relying on BitLocker for full-disk encryption should assess their exposure and consider additional security controls, such as enabling TPM+PIN protection or using pre-boot authentication.

Microsoft has not yet released patches for these vulnerabilities, leaving systems exposed until fixes are deployed. Security teams should monitor for unusual access patterns to encrypted drives and apply workarounds where possible, such as disabling unnecessary boot options or enforcing strong PIN policies.

{{< netrunner-insight >}}

For SOC analysts, prioritize monitoring for unauthorized attempts to access BitLocker-protected drives and privilege escalation events. DevSecOps engineers should test their environments against the published PoCs to identify vulnerable configurations and implement compensating controls like Secure Boot and measured boot logs.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)**
