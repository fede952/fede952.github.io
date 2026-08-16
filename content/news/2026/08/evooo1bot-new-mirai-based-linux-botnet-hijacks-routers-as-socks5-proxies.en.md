---
title: "Evooo1Bot: New Mirai-based Linux Botnet Hijacks Routers as SOCKS5 Proxies"
date: "2026-08-16T07:24:07Z"
original_date: "2026-08-15T14:14:38"
lang: "en"
translationKey: "evooo1bot-new-mirai-based-linux-botnet-hijacks-routers-as-socks5-proxies"
slug: "evooo1bot-new-mirai-based-linux-botnet-hijacks-routers-as-socks5-proxies"
author: "NewsBot (Validated by Federico Sella)"
description: "Evooo1Bot, a modular Mirai variant, targets internet-facing gateways, turning routers into SOCKS5 relay nodes for stealthy traffic."
original_url: "https://www.bleepingcomputer.com/news/security/new-evooo1bot-linux-botnet-turns-routers-into-traffic-relay-nodes/"
source: "BleepingComputer"
severity: "High"
target: "Internet-facing gateway devices"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Evooo1Bot, a modular Mirai variant, targets internet-facing gateways, turning routers into SOCKS5 relay nodes for stealthy traffic.

{{< cyber-report severity="High" source="BleepingComputer" target="Internet-facing gateway devices" >}}

A new Mirai-based Linux botnet named Evooo1Bot has been observed targeting internet-facing gateway devices, such as routers and other network appliances. The malware is modular in design, allowing it to be updated with new functionalities after initial compromise.

{{< ad-banner >}}

Once infected, the compromised devices are repurposed as SOCKS5 traffic relay nodes. This enables the botnet operators to route malicious traffic through a distributed network of hijacked routers, obscuring the origin of attacks and potentially evading network-based defenses.

The use of SOCKS5 relays is a notable evolution from typical Mirai DDoS functionality, indicating a shift toward stealthier, proxy-based operations. Organizations should ensure that gateway devices are patched, default credentials are changed, and remote management interfaces are not exposed to the internet.

{{< netrunner-insight >}}

For SOC analysts, this highlights the importance of monitoring for unusual outbound connections from network devices, as SOCKS5 relays can be used to tunnel malicious traffic. DevSecOps teams should harden gateway devices by disabling unused services, enforcing strong authentication, and segmenting management interfaces. Proactive threat hunting for Mirai variants is essential, as they continue to evolve beyond simple DDoS tools.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/new-evooo1bot-linux-botnet-turns-routers-into-traffic-relay-nodes/)**
