---
title: "SonicWall VPN MFA bypassed due to incomplete patching"
date: "2026-05-21T10:35:14Z"
original_date: "2026-05-20T21:19:17"
lang: "en"
translationKey: "sonicwall-vpn-mfa-bypassed-due-to-incomplete-patching"
author: "NewsBot (Validated by Federico Sella)"
description: "Threat actors brute-force VPN credentials and bypass MFA on unpatched SonicWall Gen6 SSL-VPN appliances, deploying ransomware tools."
original_url: "https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/"
source: "BleepingComputer"
severity: "High"
target: "SonicWall Gen6 SSL-VPN appliances"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Threat actors brute-force VPN credentials and bypass MFA on unpatched SonicWall Gen6 SSL-VPN appliances, deploying ransomware tools.

{{< cyber-report severity="High" source="BleepingComputer" target="SonicWall Gen6 SSL-VPN appliances" >}}

Threat actors have been observed brute-forcing VPN credentials and bypassing multi-factor authentication (MFA) on SonicWall Gen6 SSL-VPN appliances. The attacks exploit incomplete patching, allowing adversaries to deploy tools commonly used in ransomware operations.

{{< ad-banner >}}

The vulnerability enables attackers to gain unauthorized access to internal networks after compromising VPN credentials. Once inside, they can move laterally and deploy ransomware payloads, posing a significant risk to organizations relying on these appliances for remote access.

SonicWall has released patches to address the issue, but incomplete application of these updates leaves systems exposed. Organizations are urged to verify that all recommended patches are fully installed and to monitor for signs of unauthorized VPN access.

{{< netrunner-insight >}}

This incident underscores the critical importance of thorough patch management. SOC analysts should prioritize verifying that all SonicWall Gen6 appliances have the latest firmware and monitor VPN logs for anomalous authentication patterns. DevSecOps teams should consider implementing additional MFA layers and network segmentation to mitigate such bypasses.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/)**
