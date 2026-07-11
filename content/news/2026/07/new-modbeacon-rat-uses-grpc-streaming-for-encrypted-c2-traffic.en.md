---
title: "New MODBEACON RAT Uses gRPC Streaming for Encrypted C2 Traffic"
date: "2026-07-11T08:43:59Z"
original_date: "2026-07-10T13:15:23"
lang: "en"
translationKey: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
slug: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "China-linked Silver Fox group deploys Rust-based MODBEACON RAT via SEO poisoning, using gRPC streaming for encrypted C2 communication."
original_url: "https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html"
source: "The Hacker News"
severity: "High"
target: "Windows users via counterfeit installers"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

China-linked Silver Fox group deploys Rust-based MODBEACON RAT via SEO poisoning, using gRPC streaming for encrypted C2 communication.

{{< cyber-report severity="High" source="The Hacker News" target="Windows users via counterfeit installers" >}}

The China-linked cybercrime group Silver Fox has been attributed to a new Rust-based remote access trojan (RAT) called MODBEACON. The malware uses gRPC streaming for encrypted command-and-control (C2) traffic, making detection more challenging.

{{< ad-banner >}}

According to Chinese cybersecurity company QiAnXin, Silver Fox propagates MODBEACON via counterfeit installers using SEO poisoning techniques. While the group may appear as a low-sophistication, high-activity operation, their true organizational capabilities are more advanced.

The use of gRPC streaming for C2 communication represents a novel technique for malware, as it leverages HTTP/2 and protocol buffers to blend in with legitimate traffic. Security teams should monitor for unusual gRPC traffic and investigate SEO-poisoned download sites.

{{< netrunner-insight >}}

SOC analysts should add gRPC traffic analysis to their detection pipelines, as MODBEACON's use of streaming RPCs can evade traditional network signatures. DevSecOps teams must verify the integrity of software downloads and consider blocking known SEO poisoning domains. This RAT underscores the need for proactive threat hunting against Rust-based malware.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html)**
