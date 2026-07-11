---
title: "新型MODBEACON RAT利用gRPC流式传输实现加密C2通信"
date: "2026-07-11T08:43:59Z"
original_date: "2026-07-10T13:15:23"
lang: "zh-cn"
translationKey: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
slug: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "与中国关联的Silver Fox组织通过SEO投毒部署基于Rust的MODBEACON RAT，使用gRPC流式传输进行加密C2通信。"
original_url: "https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html"
source: "The Hacker News"
severity: "High"
target: "通过假冒安装程序针对Windows用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

与中国关联的Silver Fox组织通过SEO投毒部署基于Rust的MODBEACON RAT，使用gRPC流式传输进行加密C2通信。

{{< cyber-report severity="High" source="The Hacker News" target="通过假冒安装程序针对Windows用户" >}}

与中国关联的网络犯罪组织Silver Fox被指使用一种名为MODBEACON的新型基于Rust的远程访问木马（RAT）。该恶意软件利用gRPC流式传输进行加密的命令与控制（C2）通信，使得检测更加困难。

{{< ad-banner >}}

据中国网络安全公司奇安信称，Silver Fox通过SEO投毒技术使用假冒安装程序传播MODBEACON。虽然该组织可能表现为低复杂度、高活跃度的操作，但其真正的组织能力更为先进。

使用gRPC流式传输进行C2通信代表了恶意软件的一种新技术，因为它利用HTTP/2和协议缓冲区来混入合法流量。安全团队应监控异常的gRPC流量，并调查被SEO投毒的下载站点。

{{< netrunner-insight >}}

SOC分析师应将gRPC流量分析添加到检测管道中，因为MODBEACON对流式RPC的使用可以规避传统的网络签名。DevSecOps团队必须验证软件下载的完整性，并考虑阻止已知的SEO投毒域名。这款RAT凸显了对基于Rust的恶意软件进行主动威胁狩猎的必要性。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html)**
