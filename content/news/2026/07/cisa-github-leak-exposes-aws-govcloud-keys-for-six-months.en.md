---
title: "CISA GitHub Leak Exposes AWS GovCloud Keys for Six Months"
date: "2026-07-14T09:01:14Z"
original_date: "2026-07-13T15:03:28"
lang: "en"
translationKey: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
slug: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
author: "NewsBot (Validated by Federico Sella)"
description: "A contractor leaked internal CISA credentials, including AWS GovCloud keys, on GitHub for six months. Experts highlight critical lessons for security teams."
original_url: "https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/"
source: "Krebs on Security"
severity: "High"
target: "CISA GitHub repository"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A contractor leaked internal CISA credentials, including AWS GovCloud keys, on GitHub for six months. Experts highlight critical lessons for security teams.

{{< cyber-report severity="High" source="Krebs on Security" target="CISA GitHub repository" >}}

The Cybersecurity and Infrastructure Security Agency (CISA) disclosed a data leak where a contractor inadvertently published dozens of internal credentials, including AWS GovCloud keys, in a public GitHub repository. The credentials remained exposed for nearly six months before KrebsOnSecurity notified the agency.

{{< ad-banner >}}

CISA's postmortem identified gaps in their initial response, such as delayed detection and lack of automated scanning for secrets in public repositories. The incident underscores the need for robust secret management and continuous monitoring of code repositories.

Experts recommend implementing pre-commit hooks, regular secret scanning, and strict access controls to prevent similar leaks. The use of ephemeral credentials and automated rotation can also mitigate the impact of exposed keys.

{{< netrunner-insight >}}

This incident is a textbook case of why secrets scanning must be integrated into CI/CD pipelines, not just post-commit. SOC analysts should prioritize alerts for public repository exposures, and DevSecOps teams should enforce least-privilege access for contractors. Automate credential rotation and consider using tools like GitLeaks or TruffleHog to catch leaks early.

{{< /netrunner-insight >}}

---

**[Read full article on Krebs on Security ›](https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/)**
