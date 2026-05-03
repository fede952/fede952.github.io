---
title: "SAP npm Packages Hit by Credential-Stealing Supply Chain Attack"
date: "2026-05-03T08:51:39Z"
original_date: "2026-04-29T16:26:00"
lang: "en"
translationKey: "sap-npm-packages-hit-by-credential-stealing-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "A campaign dubbed 'Mini Shai-Hulud' targets SAP-related npm packages with credential-stealing malware, affecting multiple packages. Researchers from several firms warn of supply chain risks."
original_url: "https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html"
source: "The Hacker News"
severity: "High"
target: "SAP-related npm packages"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A campaign dubbed 'Mini Shai-Hulud' targets SAP-related npm packages with credential-stealing malware, affecting multiple packages. Researchers from several firms warn of supply chain risks.

{{< cyber-report severity="High" source="The Hacker News" target="SAP-related npm packages" >}}

Cybersecurity researchers have uncovered a supply chain attack campaign targeting SAP-related npm packages. Dubbed 'Mini Shai-Hulud,' the campaign deploys credential-stealing malware through compromised packages, according to reports from Aikido Security, Onapsis, OX Security, SafeDep, Socket, StepSecurity, and Wiz.

{{< ad-banner >}}

The attack affects multiple npm packages associated with SAP, though specific package names and versions have not been disclosed. The malware is designed to steal credentials, potentially giving attackers access to sensitive SAP environments and downstream systems.

This incident highlights the growing threat to software supply chains, particularly for enterprise-critical platforms like SAP. Organizations using affected packages are advised to audit their dependencies and rotate any potentially compromised credentials.

{{< netrunner-insight >}}

For SOC analysts and DevSecOps teams, this attack underscores the need for rigorous dependency scanning and integrity checks on npm packages. Monitor for unusual outbound connections from SAP-related systems and consider implementing runtime application self-protection (RASP) to detect credential theft. Rotate all credentials that may have been exposed through compromised packages immediately.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)**
