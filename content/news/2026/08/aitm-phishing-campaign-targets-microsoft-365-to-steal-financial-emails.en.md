---
title: "AitM Phishing Campaign Targets Microsoft 365 to Steal Financial Emails"
date: "2026-08-08T07:47:42Z"
original_date: "2026-08-07T10:38:27"
lang: "en"
translationKey: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
slug: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
author: "NewsBot (Validated by Federico Sella)"
description: "Widespread email-driven phishing uses adversary-in-the-middle to hijack Microsoft 365 accounts, aiming to collect payroll and finance emails."
original_url: "https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html"
source: "The Hacker News"
severity: "High"
target: "Microsoft 365 accounts"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Widespread email-driven phishing uses adversary-in-the-middle to hijack Microsoft 365 accounts, aiming to collect payroll and finance emails.

{{< cyber-report severity="High" source="The Hacker News" target="Microsoft 365 accounts" >}}

Cybersecurity researchers have identified an active, widespread email-driven phishing campaign that leverages adversary-in-the-middle (AitM) techniques to compromise Microsoft 365 accounts. The campaign's primary objective is to identify key personnel involved in financial workflows and exfiltrate related email communications, particularly those concerning payroll and finance.

{{< ad-banner >}}

The attackers employ residential proxies to disguise their malicious sign-ins as ordinary consumer traffic, thereby evading detection by security controls that typically flag suspicious IP addresses. This technique allows the attackers to maintain persistence and access to the compromised accounts without raising immediate alarms.

Organizations using Microsoft 365 should be vigilant against such AitM phishing attempts, which often bypass multi-factor authentication by relaying credentials and session tokens in real time. The campaign's focus on financial data suggests a targeted effort to facilitate financial fraud or business email compromise (BEC).

{{< netrunner-insight >}}

This campaign underscores the need for phishing-resistant MFA, such as FIDO2 security keys, and continuous monitoring for anomalous sign-ins, especially those originating from residential IP ranges. SOC teams should also prioritize detection rules for AitM toolkits and enforce conditional access policies that restrict access based on risk signals. DevSecOps engineers should consider implementing session binding and device compliance checks to mitigate token relay attacks.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html)**
