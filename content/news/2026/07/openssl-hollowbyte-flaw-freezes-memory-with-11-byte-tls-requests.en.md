---
title: "OpenSSL HollowByte Flaw Freezes Memory with 11-Byte TLS Requests"
date: "2026-07-18T08:44:53Z"
original_date: "2026-07-17T20:20:53"
lang: "en"
translationKey: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
slug: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
author: "NewsBot (Validated by Federico Sella)"
description: "A denial-of-service bug in OpenSSL, dubbed HollowByte, lets attackers freeze server memory using tiny TLS requests. Okta's Red Team reported it; fix shipped without CVE."
original_url: "https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html"
source: "The Hacker News"
severity: "High"
target: "OpenSSL servers on glibc systems"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A denial-of-service bug in OpenSSL, dubbed HollowByte, lets attackers freeze server memory using tiny TLS requests. Okta's Red Team reported it; fix shipped without CVE.

{{< cyber-report severity="High" source="The Hacker News" target="OpenSSL servers on glibc systems" >}}

A newly disclosed denial-of-service vulnerability in OpenSSL, named HollowByte by Okta's Red Team, allows an attacker to exhaust server memory with just 11 bytes of TLS handshake data. The flaw causes an unpatched OpenSSL server to allocate up to 131 KB of memory for a message that never arrives, and on systems using glibc, that memory is not freed until the process restarts.

{{< ad-banner >}}

OpenSSL shipped the fix in June 2026 without assigning a CVE identifier, issuing an advisory, or noting the change in the changelog. Okta's Red Team, which discovered and reported the bug, published details after the fix was released. The vulnerability affects OpenSSL servers running on glibc-based systems, making them susceptible to memory exhaustion attacks.

While the attack requires only a single TLS ClientHello of 11 bytes, the impact can be severe in environments where OpenSSL processes are long-lived and handle many concurrent connections. Organizations running OpenSSL on glibc should prioritize applying the June 2026 update to prevent potential denial-of-service conditions.

{{< netrunner-insight >}}

This is a classic resource exhaustion vector that bypasses traditional rate limiting because the malicious traffic looks like normal TLS handshakes. SOC analysts should monitor for sudden spikes in memory usage on OpenSSL servers, and DevSecOps teams should verify that the June 2026 OpenSSL update is deployed, even without a CVE. The lack of a CVE does not reduce the operational risk—treat this as a high-priority patch.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html)**
