---
title: "Miasma Worm Hits 73 Microsoft GitHub Repos in Supply Chain Attack"
date: "2026-06-07T09:57:27Z"
original_date: "2026-06-06T06:58:04"
lang: "en"
translationKey: "miasma-worm-hits-73-microsoft-github-repos-in-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft's GitHub repositories across Azure, Azure-Samples, Microsoft, and MicrosoftDocs were compromised by the Miasma self-replicating worm, impacting 73 repos."
original_url: "https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html"
source: "The Hacker News"
severity: "High"
target: "Microsoft GitHub repositories"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft's GitHub repositories across Azure, Azure-Samples, Microsoft, and MicrosoftDocs were compromised by the Miasma self-replicating worm, impacting 73 repos.

{{< cyber-report severity="High" source="The Hacker News" target="Microsoft GitHub repositories" >}}

The Miasma self-replicating supply chain attack campaign has expanded to target Microsoft's GitHub repositories, compromising 73 repositories across four organizations: Azure, Azure-Samples, Microsoft, and MicrosoftDocs. The incident was reported by OpenSourceMalware, prompting GitHub to disable access to the affected repositories to contain the spread.

{{< ad-banner >}}

This attack underscores the growing threat of self-replicating malware in software supply chains. By compromising trusted repositories, attackers can inject malicious code into downstream projects that rely on these sources, potentially affecting a wide range of users and organizations.

While specific technical details of the compromise remain undisclosed, the incident highlights the need for enhanced security measures in CI/CD pipelines and repository management. Organizations should review their dependencies on Microsoft's GitHub repositories and monitor for any anomalous activity.

{{< netrunner-insight >}}

For SOC analysts, prioritize monitoring for unusual commits or access patterns in your own GitHub organizations. DevSecOps teams should enforce strict branch protection rules, require signed commits, and implement automated scanning for self-replicating malware in CI/CD pipelines. This incident is a stark reminder that even major vendors like Microsoft are not immune to supply chain attacks.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html)**
