---
title: "Kimwolf v7 Android Botnet Uses HTTP/2 to Evade DDoS Detection"
date: "2026-08-16T07:27:33Z"
original_date: "2026-08-11T19:36:37"
lang: "en"
translationKey: "kimwolf-v7-android-botnet-uses-http-2-to-evade-ddos-detection"
slug: "kimwolf-v7-android-botnet-uses-http-2-to-evade-ddos-detection"
author: "NewsBot (Validated by Federico Sella)"
description: "New Kimwolf v7 Android and IoT botnet discovered by Unit 42 uses HTTP/2 to make DDoS traffic look like legitimate browsing, improving resilience."
original_url: "https://thehackernews.com/2026/08/kimwolf-v7-android-botnet-makes-http2.html"
source: "The Hacker News"
severity: "Medium"
target: "Android and IoT devices"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

New Kimwolf v7 Android and IoT botnet discovered by Unit 42 uses HTTP/2 to make DDoS traffic look like legitimate browsing, improving resilience.

{{< cyber-report severity="Medium" source="The Hacker News" target="Android and IoT devices" >}}

Cybersecurity researchers have uncovered a new version of the Kimwolf/AISURU botnet, designated Kimwolf v7, which targets Android and Internet of Things (IoT) devices. This variant was identified by Palo Alto Networks Unit 42 in February 2026 and introduces significant enhancements aimed at improving operational resilience and executing distributed denial-of-service (DDoS) attacks.

{{< ad-banner >}}

A key improvement in Kimwolf v7 is its adoption of HTTP/2-based traffic, which allows the botnet to make its DDoS attack traffic appear as legitimate browsing activity. This technique is designed to evade detection by security solutions that may not effectively distinguish between malicious and benign HTTP/2 traffic, thereby increasing the difficulty of mitigating such attacks.

The discovery highlights the evolving sophistication of botnet operators, who are continuously adapting their tools to bypass modern security defenses. Organizations with Android and IoT devices in their networks should be aware of this threat and consider updating their detection mechanisms to account for HTTP/2-based anomalies.

{{< netrunner-insight >}}

For SOC analysts, this underscores the need to baseline normal HTTP/2 traffic patterns and deploy behavioral analytics that can spot anomalies even when traffic appears legitimate. DevSecOps teams should ensure that DDoS mitigation solutions are capable of inspecting HTTP/2 traffic and consider implementing rate limiting and anomaly detection at the application layer to counter such evasive techniques.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/kimwolf-v7-android-botnet-makes-http2.html)**
