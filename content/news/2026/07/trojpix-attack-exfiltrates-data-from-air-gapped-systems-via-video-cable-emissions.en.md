---
title: "TrojPix Attack Exfiltrates Data from Air-Gapped Systems via Video Cable Emissions"
date: "2026-07-06T11:24:53Z"
original_date: "2026-07-06T08:50:54"
lang: "en"
translationKey: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
slug: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
author: "NewsBot (Validated by Federico Sella)"
description: "Researchers demonstrate TrojPix, a technique that leaks data from air-gapped computers by modulating on-screen pixels to emit faint radio signals from video cables, requiring prior malware access."
original_url: "https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html"
source: "The Hacker News"
severity: "Medium"
target: "Air-gapped systems"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Researchers demonstrate TrojPix, a technique that leaks data from air-gapped computers by modulating on-screen pixels to emit faint radio signals from video cables, requiring prior malware access.

{{< cyber-report severity="Medium" source="The Hacker News" target="Air-gapped systems" >}}

Researchers at Shandong University have unveiled TrojPix, a novel attack that exfiltrates data from air-gapped computers by exploiting electromagnetic emissions from video cables. The technique subtly alters on-screen pixels in a manner imperceptible to the human eye, causing the video cable to radiate a faint radio signal that can be captured and decoded by a nearby receiver.

{{< ad-banner >}}

TrojPix requires prior malware installation on the target system to manipulate pixel values. This approach achieves significantly higher data transfer rates compared to previous air-gap covert channels, making it a practical threat for highly secure environments. The attack highlights the ongoing challenge of protecting data even in physically isolated networks.

While the technique is sophisticated, its reliance on pre-existing malware limits its applicability. Organizations should focus on preventing initial compromise through robust endpoint security and monitoring for unusual electromagnetic emissions in sensitive areas.

{{< netrunner-insight >}}

For SOC analysts, TrojPix underscores that air-gapped systems are not immune to data exfiltration. Monitor for anomalous electromagnetic signals near sensitive workstations and enforce strict physical security. DevSecOps teams should consider shielding video cables and implementing pixel-level anomaly detection where feasible.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html)**
