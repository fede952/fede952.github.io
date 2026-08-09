---
title: "CSS Attacks Escape Email Boundaries to Steal Passwords and Tokens"
date: "2026-08-09T07:52:16Z"
original_date: "2026-08-08T08:03:57"
lang: "en"
translationKey: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
slug: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "New research reveals CSS-based attacks that break out of email content to hijack webmail interfaces, stealing credentials and tokens across major providers."
original_url: "https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html"
source: "The Hacker News"
severity: "High"
target: "Webmail interfaces (Outlook, Gmail, etc.)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

New research reveals CSS-based attacks that break out of email content to hijack webmail interfaces, stealing credentials and tokens across major providers.

{{< cyber-report severity="High" source="The Hacker News" target="Webmail interfaces (Outlook, Gmail, etc.)" >}}

Security researcher Gareth from PortSwigger has uncovered a novel class of attacks that leverage CSS to break the intended isolation between email content and the surrounding webmail interface. By crafting malicious emails, an attacker can cause content to escape its message boundary and interfere with the webmail's own UI, potentially capturing passwords, stealing session tokens, and hijacking trusted user actions.

{{< ad-banner >}}

The research demonstrates attack chains affecting major webmail providers including Outlook, Gmail, Fastmail, Proton Mail, Yahoo Mail, and AOL Mail. Beyond credential theft, the techniques can be used to take over third-party accounts, leak sensitive tokens, and even manipulate AI tools that read email, expanding the attack surface significantly.

These findings highlight a fundamental weakness in how webmail clients render untrusted content. While no specific CVE has been assigned yet, the impact is severe, and organizations relying on webmail should monitor for updates and consider additional security layers to mitigate potential exploitation.

{{< netrunner-insight >}}

This research underscores that email is not just a vector for malware but can also be a weapon against the very interface users trust. SOC analysts should treat suspicious emails as potential UI-breaking payloads, not just phishing lures. DevSecOps teams should review how their webmail clients sandbox content and consider enforcing strict Content Security Policy (CSP) headers to limit CSS-based breakout attempts.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html)**
