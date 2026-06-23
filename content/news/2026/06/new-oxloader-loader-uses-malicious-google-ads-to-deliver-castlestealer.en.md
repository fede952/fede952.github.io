---
title: "New OXLOADER Loader Uses Malicious Google Ads to Deliver CastleStealer"
date: "2026-06-23T10:32:59Z"
original_date: "2026-06-22T13:20:12"
lang: "en"
translationKey: "new-oxloader-loader-uses-malicious-google-ads-to-deliver-castlestealer"
author: "NewsBot (Validated by Federico Sella)"
description: "Elastic Security Labs reveals a campaign using malicious Google Ads to distribute the OXLOADER loader, which delivers CastleStealer malware, likely operated by Russian-speaking threat actors."
original_url: "https://thehackernews.com/2026/06/new-oxloader-loader-uses-malicious.html"
source: "The Hacker News"
severity: "High"
target: "Users clicking malicious Google Ads"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Elastic Security Labs reveals a campaign using malicious Google Ads to distribute the OXLOADER loader, which delivers CastleStealer malware, likely operated by Russian-speaking threat actors.

{{< cyber-report severity="High" source="The Hacker News" target="Users clicking malicious Google Ads" >}}

Cybersecurity researchers at Elastic Security Labs have uncovered a new campaign that leverages malicious Google Ads to distribute a previously unreported malware loader named OXLOADER. The loader is used to deliver CastleStealer, a credential-stealing malware, to unsuspecting victims.

{{< ad-banner >}}

The campaign is believed to be financially motivated and likely operated by Russian-speaking threat actors. The use of Google Ads as an initial infection vector highlights the evolving tactics of cybercriminals to bypass traditional security measures and reach a wider audience.

Organizations and individuals are advised to exercise caution when clicking on advertisements, even from seemingly legitimate sources. Implementing ad-blockers and maintaining up-to-date security software can help mitigate the risk of such attacks.

{{< netrunner-insight >}}

For SOC analysts, monitoring for unusual ad clicks and subsequent network connections to unknown domains is critical. DevSecOps teams should consider blocking ad-related domains in proxy filters and educating users about the risks of clicking on ads, even from trusted search engines.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/06/new-oxloader-loader-uses-malicious.html)**
