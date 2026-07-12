---
title: "Fake Microsoft Entra Passkey Enrollment Targets M365 Users in Data Extortion Campaign"
date: "2026-07-12T09:00:42Z"
original_date: "2026-07-10T10:30:20"
lang: "en"
translationKey: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
slug: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "Threat actor O-UNC-066 uses voice-based phishing to trick users into enrolling a fake Entra passkey, aiming to compromise Microsoft 365 accounts for data extortion."
original_url: "https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html"
source: "The Hacker News"
severity: "High"
target: "Microsoft 365 users"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Threat actor O-UNC-066 uses voice-based phishing to trick users into enrolling a fake Entra passkey, aiming to compromise Microsoft 365 accounts for data extortion.

{{< cyber-report severity="High" source="The Hacker News" target="Microsoft 365 users" >}}

A threat actor tracked as O-UNC-066 by Okta has been observed conducting voice-based phishing attacks targeting Microsoft 365 users across multiple sectors. The attackers impersonate legitimate security requests to trick victims into enrolling a fake Entra passkey, thereby granting the adversary unauthorized access to their accounts.

{{< ad-banner >}}

The campaign utilizes a panel-controlled phishing kit specifically designed to intercept the passkey enrollment process. Once the attacker gains access, they aim to carry out data extortion, exfiltrating sensitive information and demanding ransom. The attacks highlight a growing trend of using voice channels to bypass traditional email-based phishing defenses.

Organizations are advised to implement multi-factor authentication (MFA) with hardware security keys and to educate users about verifying any unsolicited security requests via alternate communication channels. Monitoring for anomalous passkey enrollment activities can help detect such attacks early.

{{< netrunner-insight >}}

This attack underscores the importance of treating voice-based security requests with the same skepticism as phishing emails. SOC analysts should monitor for unusual passkey enrollment attempts and ensure that MFA enrollment processes require out-of-band verification. DevSecOps teams should consider implementing conditional access policies that restrict passkey enrollment to trusted devices and locations.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html)**
