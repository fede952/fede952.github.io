---
title: "Mini Shai-Hulud Campaign Compromises @antv npm Packages via Maintainer Account"
date: "2026-05-19T10:37:35Z"
original_date: "2026-05-19T04:54:17"
lang: "en"
translationKey: "mini-shai-hulud-campaign-compromises-antv-npm-packages-via-maintainer-account"
author: "NewsBot (Validated by Federico Sella)"
description: "Attackers compromise the @antv maintainer account 'atool' to push malicious npm packages, including echarts-for-react with 1.1M weekly downloads, in the ongoing Mini Shai-Hulud supply chain attack wave."
original_url: "https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html"
source: "The Hacker News"
severity: "High"
target: "@antv npm ecosystem"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Attackers compromise the @antv maintainer account 'atool' to push malicious npm packages, including echarts-for-react with 1.1M weekly downloads, in the ongoing Mini Shai-Hulud supply chain attack wave.

{{< cyber-report severity="High" source="The Hacker News" target="@antv npm ecosystem" >}}

Cybersecurity researchers have identified a new software supply chain attack campaign targeting the @antv npm ecosystem. The attackers compromised the npm maintainer account 'atool' to publish malicious versions of several packages, including echarts-for-react, a widely used React wrapper for Apache ECharts with approximately 1.1 million weekly downloads.

{{< ad-banner >}}

This campaign is part of the ongoing Mini Shai-Hulud attack wave, which has previously targeted other open-source ecosystems. The compromised packages likely contain malicious code designed to exfiltrate sensitive data or establish backdoors in development environments.

Organizations using any @antv packages should immediately audit their dependencies for signs of compromise, rotate credentials, and review recent changes in their lock files. The full scope of affected packages and the exact payload remain under investigation.

{{< netrunner-insight >}}

This attack underscores the critical need for supply chain security measures such as package integrity verification, multi-factor authentication for maintainer accounts, and automated dependency scanning. SOC analysts should prioritize monitoring for anomalous outbound traffic from build pipelines, while DevSecOps teams must enforce strict access controls on package publishing accounts.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html)**
