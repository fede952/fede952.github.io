---
title: "OpenSSL HollowByte 漏洞：11字节TLS请求冻结服务器内存"
date: "2026-07-18T08:44:53Z"
original_date: "2026-07-17T20:20:53"
lang: "zh-cn"
translationKey: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
slug: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
author: "NewsBot (Validated by Federico Sella)"
description: "OpenSSL 中名为 HollowByte 的拒绝服务漏洞允许攻击者利用微小的 TLS 请求冻结服务器内存。Okta 红队报告了该漏洞；修复已发布，但未分配 CVE。"
original_url: "https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html"
source: "The Hacker News"
severity: "High"
target: "运行在 glibc 系统上的 OpenSSL 服务器"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

OpenSSL 中名为 HollowByte 的拒绝服务漏洞允许攻击者利用微小的 TLS 请求冻结服务器内存。Okta 红队报告了该漏洞；修复已发布，但未分配 CVE。

{{< cyber-report severity="High" source="The Hacker News" target="运行在 glibc 系统上的 OpenSSL 服务器" >}}

Okta 红队将 OpenSSL 中一个新披露的拒绝服务漏洞命名为 HollowByte，攻击者仅需 11 字节的 TLS 握手数据即可耗尽服务器内存。该漏洞导致未打补丁的 OpenSSL 服务器为一条永远不会到达的消息分配高达 131 KB 的内存，而在使用 glibc 的系统上，该内存直到进程重启才会被释放。

{{< ad-banner >}}

OpenSSL 于 2026 年 6 月发布了修复，但未分配 CVE 标识符、未发布安全公告，也未在变更日志中注明。发现并报告该漏洞的 Okta 红队在修复发布后公布了细节。该漏洞影响运行在基于 glibc 系统上的 OpenSSL 服务器，使其容易遭受内存耗尽攻击。

虽然攻击仅需一个 11 字节的 TLS ClientHello，但在 OpenSSL 进程长期运行且处理大量并发连接的环境中，影响可能十分严重。在 glibc 上运行 OpenSSL 的组织应优先应用 2026 年 6 月的更新，以防止潜在的拒绝服务情况。

{{< netrunner-insight >}}

这是一个经典的资源耗尽攻击向量，由于恶意流量看起来像正常的 TLS 握手，因此绕过了传统的速率限制。SOC 分析师应监控 OpenSSL 服务器上内存使用的突然峰值，DevSecOps 团队应确保部署了 2026 年 6 月的 OpenSSL 更新，即使没有 CVE。缺少 CVE 并不会降低操作风险——请将此视为高优先级补丁。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html)**
