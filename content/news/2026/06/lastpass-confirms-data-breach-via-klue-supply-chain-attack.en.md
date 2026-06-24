---
title: "LastPass confirms data breach via Klue supply chain attack"
date: "2026-06-24T10:23:36Z"
original_date: "2026-06-23T13:58:25"
lang: "en"
translationKey: "lastpass-confirms-data-breach-via-klue-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "LastPass disclosed that attackers stole OAuth tokens from a third-party app, Klue, to access customer data in its Salesforce environment."
original_url: "https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "LastPass Salesforce environment"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

LastPass disclosed that attackers stole OAuth tokens from a third-party app, Klue, to access customer data in its Salesforce environment.

{{< cyber-report severity="High" source="BleepingComputer" target="LastPass Salesforce environment" >}}

LastPass has confirmed that hackers accessed customer data from its Salesforce environment after stealing the company's OAuth tokens in the Klue supply chain attack earlier this month. The breach, disclosed on June 23, 2026, highlights the risks of third-party integrations and token theft.

{{< ad-banner >}}

The attackers used compromised OAuth tokens from Klue, a third-party application, to gain unauthorized access to LastPass's Salesforce instance. This supply chain attack allowed the threat actors to exfiltrate customer data without triggering typical authentication alerts.

LastPass is notifying affected customers and has revoked the compromised tokens. The company is also reviewing its third-party access policies to prevent similar incidents. This breach underscores the importance of monitoring OAuth token usage and implementing strict access controls for integrated services.

{{< netrunner-insight >}}

This incident is a textbook example of supply chain risk via OAuth token abuse. SOC analysts should prioritize monitoring for anomalous token usage and implement token expiration policies. DevSecOps teams must enforce least-privilege access for third-party integrations and consider using short-lived tokens to reduce blast radius.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/)**
