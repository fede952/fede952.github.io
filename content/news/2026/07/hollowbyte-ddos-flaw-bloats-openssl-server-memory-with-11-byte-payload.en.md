---
title: "HollowByte DDoS flaw bloats OpenSSL server memory with 11-byte payload"
date: "2026-07-19T09:04:58Z"
original_date: "2026-07-17T17:56:21"
lang: "en"
translationKey: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
slug: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
author: "NewsBot (Validated by Federico Sella)"
description: "A vulnerability dubbed HollowByte allows unauthenticated attackers to trigger a denial-of-service condition on OpenSSL servers with a malicious payload of just 11 bytes."
original_url: "https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/"
source: "BleepingComputer"
severity: "High"
target: "OpenSSL servers"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A vulnerability dubbed HollowByte allows unauthenticated attackers to trigger a denial-of-service condition on OpenSSL servers with a malicious payload of just 11 bytes.

{{< cyber-report severity="High" source="BleepingComputer" target="OpenSSL servers" >}}

A newly discovered vulnerability, named HollowByte, enables unauthenticated attackers to cause a denial-of-service (DoS) condition on OpenSSL servers by sending a specially crafted payload of only 11 bytes. The flaw exploits memory allocation inefficiencies, causing the server's memory to bloat and eventually exhaust available resources.

{{< ad-banner >}}

The attack does not require authentication and can be executed remotely, making it a significant threat to any organization relying on OpenSSL for secure communications. The minimal payload size allows attackers to amplify their impact with limited bandwidth, potentially overwhelming servers with minimal effort.

While no CVE identifier has been assigned yet, the vulnerability has been disclosed to the OpenSSL project, and patches are expected. In the meantime, administrators are advised to monitor memory usage and implement rate limiting or intrusion detection rules to mitigate potential exploitation.

{{< netrunner-insight >}}

For SOC analysts, this is a classic low-bandwidth, high-impact DoS vector that can bypass traditional volumetric defenses. DevSecOps teams should prioritize patching once available and consider deploying memory monitoring alerts to detect anomalous growth. The 11-byte payload makes this an ideal candidate for inclusion in threat detection rules.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/)**
