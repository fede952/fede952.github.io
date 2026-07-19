---
title: "HollowByte DDoS漏洞利用11字节载荷膨胀OpenSSL服务器内存"
date: "2026-07-19T09:04:58Z"
original_date: "2026-07-17T17:56:21"
lang: "zh-cn"
translationKey: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
slug: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
author: "NewsBot (Validated by Federico Sella)"
description: "名为HollowByte的漏洞允许未经身份验证的攻击者通过仅11字节的恶意载荷触发OpenSSL服务器的拒绝服务条件。"
original_url: "https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/"
source: "BleepingComputer"
severity: "High"
target: "OpenSSL服务器"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

名为HollowByte的漏洞允许未经身份验证的攻击者通过仅11字节的恶意载荷触发OpenSSL服务器的拒绝服务条件。

{{< cyber-report severity="High" source="BleepingComputer" target="OpenSSL服务器" >}}

新发现的漏洞HollowByte使未经身份验证的攻击者能够通过发送仅11字节的特制载荷，在OpenSSL服务器上引发拒绝服务（DoS）条件。该漏洞利用内存分配的低效性，导致服务器内存膨胀并最终耗尽可用资源。

{{< ad-banner >}}

攻击无需身份验证且可远程执行，对任何依赖OpenSSL进行安全通信的组织构成重大威胁。极小的载荷大小使攻击者能够以有限的带宽放大影响，以最小努力压垮服务器。

虽然尚未分配CVE标识符，但该漏洞已披露给OpenSSL项目，预计将发布补丁。在此期间，建议管理员监控内存使用情况，并实施速率限制或入侵检测规则以缓解潜在利用。

{{< netrunner-insight >}}

对于SOC分析师而言，这是一个典型的低带宽、高影响的DoS向量，可绕过传统的容量型防御。DevSecOps团队应在补丁可用时优先修补，并考虑部署内存监控告警以检测异常增长。11字节的载荷使其成为威胁检测规则中理想的候选对象。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/)**
