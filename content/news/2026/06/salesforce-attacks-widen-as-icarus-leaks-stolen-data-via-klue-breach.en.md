---
title: "Salesforce Attacks Widen as Icarus Leaks Stolen Data via Klue Breach"
date: "2026-06-24T10:22:11Z"
original_date: "2026-06-23T20:44:09"
lang: "en"
translationKey: "salesforce-attacks-widen-as-icarus-leaks-stolen-data-via-klue-breach"
author: "NewsBot (Validated by Federico Sella)"
description: "Attackers exploited Klue's OAuth tokens to access Salesforce instances; more victims emerge as Icarus leaks stolen data."
original_url: "https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data"
source: "Dark Reading"
severity: "High"
target: "Salesforce instances via Klue OAuth tokens"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Attackers exploited Klue's OAuth tokens to access Salesforce instances; more victims emerge as Icarus leaks stolen data.

{{< cyber-report severity="High" source="Dark Reading" target="Salesforce instances via Klue OAuth tokens" >}}

The scope of ongoing attacks against Salesforce has expanded as threat actors, tracked as Icarus, leak data stolen from multiple victims. The attackers initially breached application vendor Klue and leveraged its OAuth tokens to gain unauthorized access to customers' Salesforce environments.

{{< ad-banner >}}

According to Dark Reading, new victims have emerged following the initial disclosure, indicating that the attack campaign is broader than previously understood. The use of OAuth tokens allowed the attackers to bypass traditional authentication controls and directly access Salesforce data without triggering typical alerts.

Organizations using Salesforce integrations with third-party vendors like Klue are urged to audit OAuth token permissions and monitor for anomalous access patterns. The Icarus group has begun leaking stolen data, increasing the urgency for affected companies to respond.

{{< netrunner-insight >}}

This attack underscores the risk of OAuth token abuse in SaaS ecosystems. SOC analysts should prioritize monitoring for unusual API calls and token usage from integrated third-party apps. DevSecOps teams must enforce strict token lifecycle management and implement just-in-time permissions to limit blast radius.

{{< /netrunner-insight >}}

---

**[Read full article on Dark Reading ›](https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data)**
