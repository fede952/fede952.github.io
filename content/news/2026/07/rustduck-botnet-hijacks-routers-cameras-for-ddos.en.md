---
title: "RustDuck Botnet Hijacks Routers, Cameras for DDoS"
date: "2026-07-01T10:41:08Z"
original_date: "2026-06-30T17:45:25"
lang: "en"
translationKey: "rustduck-botnet-hijacks-routers-cameras-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "A new two-stage malware family called RustDuck is hijacking home routers, IP cameras, Android boxes, and poorly secured servers to build a DDoS network, tracked since February 2026."
original_url: "https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html"
source: "The Hacker News"
severity: "High"
target: "Routers, IP cameras, Android boxes, servers"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A new two-stage malware family called RustDuck is hijacking home routers, IP cameras, Android boxes, and poorly secured servers to build a DDoS network, tracked since February 2026.

{{< cyber-report severity="High" source="The Hacker News" target="Routers, IP cameras, Android boxes, servers" >}}

Researchers at QiAnXin's XLab have been tracking a new two-stage malware family called RustDuck since February 2026. The botnet hijacks home routers, IP cameras, Android boxes, and poorly secured servers, stitching them into a network designed to knock websites and online services offline via DDoS attacks.

{{< ad-banner >}}

The malware is notable for being rebuilt in Rust, a memory-safe language that complicates analysis and reverse engineering. While the botnet's current size is not massive, its rapid evolution and adaptability pose a growing threat to internet infrastructure.

RustDuck represents a shift in botnet development, leveraging Rust's performance and safety features to create more resilient and harder-to-detect malware. The end goal is to build a robust DDoS network capable of taking down major targets.

{{< netrunner-insight >}}

For SOC analysts: monitor for unusual outbound traffic from IoT devices and routers, as RustDuck's two-stage infection may evade traditional signatures. DevSecOps teams should enforce strict network segmentation and disable unnecessary services on exposed devices to reduce the attack surface.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html)**
