---
title: "Fake Browser Update on Hotel Wi-Fi Delivers CornFlake RAT"
date: "2026-08-01T09:04:02Z"
original_date: "2026-08-01T06:29:05"
lang: "en"
translationKey: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
slug: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft warns of CaptiveCrunch operation using hijacked hotel Wi-Fi to push fake updates and deliver CornFlake surveillance malware."
original_url: "https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html"
source: "The Hacker News"
severity: "High"
target: "Hotel Wi-Fi users"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft warns of CaptiveCrunch operation using hijacked hotel Wi-Fi to push fake updates and deliver CornFlake surveillance malware.

{{< cyber-report severity="High" source="The Hacker News" target="Hotel Wi-Fi users" >}}

Microsoft has disclosed a new campaign tracked as CaptiveCrunch, which leverages hijacked hotel Wi-Fi networks to serve fake browser updates. These updates are actually a remote access trojan (RAT) named CornFlake, capable of capturing webcam images, microphone audio, and keystrokes, effectively turning infected devices into surveillance tools.

{{< ad-banner >}}

The operation is attributed to Storm-2945, which Microsoft assesses as an operational sub-cluster of the well-known threat group Midnight Blizzard. This suggests a high level of sophistication and resources, as the attack chain involves compromising the network infrastructure of hotels to intercept and redirect user traffic to malicious update pages.

While the report does not specify a particular CVE or CVSS score, the attack vector is notable for its use of a trusted environment (hotel Wi-Fi) to deliver malware. Travelers and business professionals are particularly at risk, as they often rely on public Wi-Fi and may be more likely to accept browser update prompts without scrutiny.

{{< netrunner-insight >}}

This campaign underscores the importance of treating any browser update prompt over untrusted networks with suspicion. SOC analysts should monitor for unusual outbound connections from endpoints that have recently connected to hotel or public Wi-Fi, and consider blocking or flagging update-related domains that are not on the organization's allowlist. For DevSecOps, enforcing strict update policies and using enterprise-grade VPNs for remote workers can mitigate the risk of such watering-hole style attacks.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html)**
