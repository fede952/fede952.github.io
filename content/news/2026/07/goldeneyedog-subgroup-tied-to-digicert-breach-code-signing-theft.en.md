---
title: "GoldenEyeDog Subgroup Tied to DigiCert Breach, Code-Signing Theft"
date: "2026-07-18T08:46:42Z"
original_date: "2026-07-17T16:39:16"
lang: "en"
translationKey: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
slug: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "Researchers attribute the April 2026 DigiCert incident to CylindricalCanine, a subgroup of Chinese cybercrime group GoldenEyeDog, known for targeting gambling and gaming sectors."
original_url: "https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html"
source: "The Hacker News"
severity: "High"
target: "DigiCert code-signing infrastructure"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Researchers attribute the April 2026 DigiCert incident to CylindricalCanine, a subgroup of Chinese cybercrime group GoldenEyeDog, known for targeting gambling and gaming sectors.

{{< cyber-report severity="High" source="The Hacker News" target="DigiCert code-signing infrastructure" >}}

Cybersecurity researchers have attributed the April 2026 security incident at DigiCert to a threat activity cluster named CylindricalCanine. The group is described as a sub-group of GoldenEyeDog (also known as APT-Q-27, Dragon Breath, and Miuuti Group), a Chinese cybercrime group that historically targets the gambling and gaming sectors.

{{< ad-banner >}}

The breach involved the theft of code-signing certificates, which could enable the threat actors to sign malicious software with legitimate credentials, bypassing security controls. Expel shared technical details of the event, highlighting the sophisticated nature of the operation.

Organizations that rely on DigiCert-issued certificates should review their certificate inventories and monitor for any unauthorized use. The incident underscores the risks posed by supply chain attacks targeting trusted certificate authorities.

{{< netrunner-insight >}}

For SOC analysts: prioritize monitoring for code-signing anomalies and unexpected certificate usage. DevSecOps teams should enforce strict certificate lifecycle management and consider short-lived certificates to limit exposure from theft.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html)**
