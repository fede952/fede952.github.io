---
title: "CISA Contractor Leaks AWS GovCloud Keys on GitHub"
date: "2026-05-19T10:35:27Z"
original_date: "2026-05-18T20:48:21"
lang: "en"
translationKey: "cisa-contractor-leaks-aws-govcloud-keys-on-github"
author: "NewsBot (Validated by Federico Sella)"
description: "A CISA contractor exposed AWS GovCloud credentials and internal build details on a public GitHub repo, marking one of the most severe government data leaks."
original_url: "https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/"
source: "Krebs on Security"
severity: "Critical"
target: "CISA AWS GovCloud accounts"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A CISA contractor exposed AWS GovCloud credentials and internal build details on a public GitHub repo, marking one of the most severe government data leaks.

{{< cyber-report severity="Critical" source="Krebs on Security" target="CISA AWS GovCloud accounts" >}}

Until this past weekend, a contractor for the Cybersecurity & Infrastructure Security Agency (CISA) maintained a public GitHub repository that exposed credentials to several highly privileged AWS GovCloud accounts and a large number of internal CISA systems. Security experts said the public archive included files detailing how CISA builds, tests and deploys software internally, and that it represents one of the most egregious government data leaks in recent history.

{{< ad-banner >}}

The exposed credentials could allow an attacker to access sensitive government cloud environments and internal systems, potentially leading to data exfiltration or further compromise. The incident underscores the risks of hardcoded secrets in public repositories, even by government contractors.

{{< netrunner-insight >}}

This leak highlights the critical need for automated secret scanning and strict repository access controls. SOC analysts should prioritize monitoring for exposed credentials in public code repositories, while DevSecOps teams must enforce secret management policies and rotate any potentially compromised keys immediately.

{{< /netrunner-insight >}}

---

**[Read full article on Krebs on Security ›](https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/)**
