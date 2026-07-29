---
title: "Compromised joyfill npm Packages Deliver RAT to Node.js Projects"
date: "2026-07-29T09:34:53Z"
original_date: "2026-07-29T04:20:57"
lang: "en"
translationKey: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
slug: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
author: "NewsBot (Validated by Federico Sella)"
description: "Beta versions of @joyfill/layouts and @joyfill/components contain an import-time JavaScript implant that resolves encrypted code to deploy a remote access trojan."
original_url: "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "Node.js developers using joyfill packages"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Beta versions of @joyfill/layouts and @joyfill/components contain an import-time JavaScript implant that resolves encrypted code to deploy a remote access trojan.

{{< cyber-report severity="High" source="The Hacker News" target="Node.js developers using joyfill packages" >}}

Two npm packages in the @joyfill namespace, @joyfill/layouts version 0.1.2-2773.beta.0 and @joyfill/components version 4.0.0-rc24-2773-beta.4, have been compromised. These beta releases contain an import-time JavaScript implant that resolves encrypted code, ultimately delivering a remote access trojan (RAT) associated with the DEV#POPPER malware family.

{{< ad-banner >}}

The malicious code executes when the packages are imported into a Node.js project, giving attackers remote access to the compromised system. The attack highlights the ongoing risk of supply chain attacks targeting the npm ecosystem, particularly through beta or release candidate versions that may receive less scrutiny.

Developers who have used these specific versions should immediately rotate credentials, scan for indicators of compromise, and review their dependency trees for any other suspicious packages. The npm registry has likely removed the malicious versions, but existing installations remain a threat.

{{< netrunner-insight >}}

This incident underscores the importance of scrutinizing pre-release packages and implementing dependency integrity checks. SOC analysts should monitor for unusual outbound connections from Node.js applications, while DevSecOps teams should enforce strict version pinning and use tools like npm audit or SCA scanners to detect known malicious packages.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html)**
