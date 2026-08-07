---
title: "TeamPCP Linked to Redis Attacks Since 2020, Later Supply Chain Campaign"
date: "2026-08-07T08:10:37Z"
original_date: "2026-08-07T06:50:05"
lang: "en"
translationKey: "teampcp-linked-to-redis-attacks-since-2020-later-supply-chain-campaign"
slug: "teampcp-linked-to-redis-attacks-since-2020-later-supply-chain-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "New analysis ties TeamPCP to Redis attacks dating back to 2020, revealing years of infrastructure compromise before supply chain focus."
original_url: "https://thehackernews.com/2026/08/teampcp-linked-to-redis-attacks-dating.html"
source: "The Hacker News"
severity: "Medium"
target: "Internet-facing infrastructure"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

New analysis ties TeamPCP to Redis attacks dating back to 2020, revealing years of infrastructure compromise before supply chain focus.

{{< cyber-report severity="Medium" source="The Hacker News" target="Internet-facing infrastructure" >}}

A recent analysis has uncovered that the threat actor known as TeamPCP has been active in the cybercrime scene since at least 2020, indicating a long history of compromising internet-facing infrastructure. The group's activities have now been linked to a later software supply chain campaign, suggesting a strategic evolution in their operations.

{{< ad-banner >}}

The connection between the earlier Redis attacks and the supply chain campaign is supported by overlapping domains, malware deployment paths, staging techniques, and backend infrastructure. These commonalities provide strong evidence that the same actor is responsible for both sets of activities, highlighting the importance of historical threat intelligence in attributing and understanding modern attacks.

For defenders, this timeline underscores the need to monitor for indicators of compromise that may span years and to consider the potential for threat actors to pivot from opportunistic attacks to more targeted supply chain operations. The findings also emphasize the value of sharing threat intelligence across organizations to identify such long-term patterns.

{{< netrunner-insight >}}

For SOC analysts, this report reinforces the importance of correlating historical indicators with current threats—TeamPCP's use of overlapping infrastructure means old IoCs may still be relevant. DevSecOps teams should treat internet-facing services like Redis as high-value targets and ensure robust patch management and monitoring, as attackers may lurk for years before striking. Supply chain defenders should also vet third-party components for ties to known malicious infrastructure, as this group demonstrates a clear progression from direct attacks to more insidious supply chain compromises.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/teampcp-linked-to-redis-attacks-dating.html)**
