---
title: "Evooo1Bot Botnet Turns Edge Devices into SOCKS5 Proxies"
date: "2026-08-18T07:31:16Z"
original_date: "2026-08-17T09:29:55"
lang: "en"
translationKey: "evooo1bot-botnet-turns-edge-devices-into-socks5-proxies"
slug: "evooo1bot-botnet-turns-edge-devices-into-socks5-proxies"
author: "NewsBot (Validated by Federico Sella)"
description: "New Linux botnet Evooo1Bot, derived from Mirai, exploits known flaws to turn edge devices into SOCKS5 proxies for stealthy attacks."
original_url: "https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html"
source: "The Hacker News"
severity: "High"
target: "Internet-facing edge devices"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

New Linux botnet Evooo1Bot, derived from Mirai, exploits known flaws to turn edge devices into SOCKS5 proxies for stealthy attacks.

{{< cyber-report severity="High" source="The Hacker News" target="Internet-facing edge devices" >}}

Cybersecurity researchers have identified a previously undocumented Linux botnet family named Evooo1Bot, which derives its core functionality from the publicly leaked Mirai botnet source code. The malware is designed to turn internet-facing devices into SOCKS5 proxies, enabling attackers to route malicious traffic through compromised devices.

{{< ad-banner >}}

While Evooo1Bot reuses the DDoS engine from Mirai, it extends the original framework with additional capabilities, including the ability to exploit known vulnerabilities in edge devices. This allows the botnet to expand its reach and maintain persistence on compromised systems.

The discovery highlights the continued evolution of Mirai-based botnets, which remain a significant threat due to their ability to recruit vulnerable IoT and edge devices into large-scale proxy networks. Organizations are advised to patch known vulnerabilities and monitor for unusual proxy traffic.

{{< netrunner-insight >}}

For SOC analysts, this botnet underscores the importance of monitoring outbound proxy traffic and detecting unusual SOCKS5 connections. DevSecOps teams should prioritize patching known vulnerabilities in edge devices and consider network segmentation to limit the impact of such botnets. The reuse of Mirai code means existing detection signatures may need updating to catch this new variant.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html)**
