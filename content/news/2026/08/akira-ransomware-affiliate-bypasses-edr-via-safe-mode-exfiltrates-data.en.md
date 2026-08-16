---
title: "Akira Ransomware Affiliate Bypasses EDR via Safe Mode, Exfiltrates Data"
date: "2026-08-16T07:35:41Z"
original_date: "2026-08-13T20:47:02"
lang: "en"
translationKey: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
slug: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
author: "NewsBot (Validated by Federico Sella)"
description: "Akira ransomware affiliate disables EDR by booting into Safe Mode with Networking, steals data but fails to encrypt. Learn how to defend."
original_url: "https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/"
source: "BleepingComputer"
severity: "High"
target: "Endpoint Detection and Response (EDR) solutions"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Akira ransomware affiliate disables EDR by booting into Safe Mode with Networking, steals data but fails to encrypt. Learn how to defend.

{{< cyber-report severity="High" source="BleepingComputer" target="Endpoint Detection and Response (EDR) solutions" >}}

Akira ransomware affiliate has been observed disabling endpoint detection and response (EDR) solutions on compromised systems by restarting the machine into Safe Mode with Networking. This technique allows the attacker to operate without EDR monitoring, as many security tools do not load in Safe Mode.

{{< ad-banner >}}

The affiliate successfully exfiltrated sensitive data from the victim's network, but the encryption phase of the attack failed. This suggests that while the EDR bypass was effective, other security controls or operational issues prevented the final ransomware payload from executing properly.

This incident highlights the importance of hardening boot configurations and monitoring for unexpected system restarts, especially into Safe Mode. Organizations should also ensure that EDR solutions have tamper protection enabled and that Safe Mode boot is restricted or monitored.

{{< netrunner-insight >}}

For SOC analysts, this is a reminder that EDR bypasses can be as simple as a reboot into Safe Mode. Monitor for unusual shutdown/restart events and consider disabling Safe Mode boot via BIOS/UEFI passwords or group policy. DevSecOps should ensure that EDR agents are configured to start in Safe Mode and that tamper protection is enforced to prevent this common evasion technique.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/)**
