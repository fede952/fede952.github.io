---
title: "Klue OAuth Breach: Icarus Hackers Steal Salesforce Tokens"
date: "2026-06-20T09:59:52Z"
original_date: "2026-06-19T22:31:04"
lang: "en"
translationKey: "klue-oauth-breach-icarus-hackers-steal-salesforce-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Klue confirms OAuth token theft impacting Salesforce integrations; Icarus extortion group claims responsibility and victim list grows."
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/"
source: "BleepingComputer"
severity: "High"
target: "Klue market intelligence platform"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Klue confirms OAuth token theft impacting Salesforce integrations; Icarus extortion group claims responsibility and victim list grows.

{{< cyber-report severity="High" source="BleepingComputer" target="Klue market intelligence platform" >}}

Market intelligence platform Klue has confirmed a security incident where threat actors stole OAuth tokens used to connect to customers' Salesforce environments. The breach, claimed by the newly emerged 'Icarus' extortion group, has led to an expanding list of affected victims.

{{< ad-banner >}}

The stolen OAuth tokens could allow attackers to access Salesforce data without requiring further authentication, posing a significant risk to Klue customers. The incident highlights the dangers of OAuth token exposure and the need for robust token lifecycle management.

As the Icarus group publicly claims the attack, organizations using Klue's Salesforce integration should immediately revoke and rotate any associated OAuth tokens and monitor for unauthorized access. The full scope of the breach remains under investigation.

{{< netrunner-insight >}}

This incident underscores the critical importance of securing OAuth tokens as sensitive credentials. SOC analysts should prioritize monitoring for anomalous Salesforce API calls and enforce token expiration policies. DevSecOps teams must implement strict token scoping and rotation mechanisms to limit blast radius in case of compromise.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/)**
