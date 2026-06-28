---
title: "Polymarket loses $3M in supply-chain attack via third-party vendor"
date: "2026-06-28T09:58:42Z"
original_date: "2026-06-26T18:04:12"
lang: "en"
translationKey: "polymarket-loses-3m-in-supply-chain-attack-via-third-party-vendor"
author: "NewsBot (Validated by Federico Sella)"
description: "Hackers injected a malicious script into Polymarket's frontend after breaching a third-party vendor, causing $3M in customer losses. The platform will fully reimburse victims."
original_url: "https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Polymarket frontend users"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Hackers injected a malicious script into Polymarket's frontend after breaching a third-party vendor, causing $3M in customer losses. The platform will fully reimburse victims.

{{< cyber-report severity="High" source="BleepingComputer" target="Polymarket frontend users" >}}

Polymarket, a decentralized prediction market platform, disclosed that attackers compromised a third-party vendor to inject a malicious script into its frontend, resulting in an estimated $3 million loss for customers. The incident, described as a supply-chain attack, targeted the platform's user interface to siphon funds.

{{< ad-banner >}}

The company stated it will fully reimburse affected customers, though the exact number of victims remains undisclosed. The breach underscores the risks associated with third-party dependencies in DeFi and crypto platforms, where frontend integrity is critical for transaction security.

While no specific CVE or CVSS score was provided, the attack vector—compromising a vendor to alter frontend code—highlights the need for robust supply-chain security measures, including code signing, integrity checks, and vendor risk assessments.

{{< netrunner-insight >}}

This incident is a textbook supply-chain attack targeting frontend integrity. SOC analysts should monitor for unauthorized script injections in web applications, especially those relying on third-party libraries or CDNs. DevSecOps teams must enforce strict content security policies (CSP), subresource integrity (SRI) checks, and regular vendor audits to mitigate such risks.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/)**
