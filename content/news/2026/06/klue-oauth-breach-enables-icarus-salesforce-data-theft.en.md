---
title: "Klue OAuth Breach Enables Icarus Salesforce Data Theft"
date: "2026-06-20T10:03:21Z"
original_date: "2026-06-18T14:19:50"
lang: "en"
translationKey: "klue-oauth-breach-enables-icarus-salesforce-data-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "Threat actors exploited an OAuth breach at Klue to steal Salesforce CRM data from multiple organizations in an ongoing extortion campaign."
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/"
source: "BleepingComputer"
severity: "High"
target: "Salesforce CRM data via OAuth"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Threat actors exploited an OAuth breach at Klue to steal Salesforce CRM data from multiple organizations in an ongoing extortion campaign.

{{< cyber-report severity="High" source="BleepingComputer" target="Salesforce CRM data via OAuth" >}}

Market intelligence platform Klue suffered an OAuth breach that allowed the threat actor group known as 'Icarus' to steal Salesforce CRM data from multiple organizations. The attackers leveraged compromised OAuth tokens to access and exfiltrate sensitive customer relationship management data, which they are now using in an extortion campaign.

{{< ad-banner >}}

The breach highlights the risks associated with OAuth integrations and third-party access to critical business platforms. Organizations using Klue's services are advised to review their OAuth token policies and monitor for unauthorized access to Salesforce instances.

Icarus has been linked to a series of data theft attacks targeting Salesforce environments. The group's modus operandi involves exploiting weak OAuth configurations and token management practices to gain persistent access to CRM data.

{{< netrunner-insight >}}

This incident underscores the critical need for rigorous OAuth token lifecycle management and continuous monitoring of third-party integrations. SOC analysts should prioritize auditing OAuth grants and implementing anomaly detection for unusual data access patterns from integrated apps.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/)**
