---
title: "isolated-vm 沙箱逃逸漏洞允许在流行 JavaScript 库中执行远程代码"
date: "2026-08-21T07:37:09Z"
original_date: "2026-08-20T13:48:24"
lang: "zh-cn"
translationKey: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
slug: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
author: "NewsBot (Validated by Federico Sella)"
description: "isolated-vm 中的严重漏洞允许沙箱化的 JavaScript 逃逸到主机，从而实现潜在的远程代码执行。所有版本直至 7.0.0 均受影响。"
original_url: "https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html"
source: "The Hacker News"
severity: "Critical"
target: "isolated-vm JavaScript 沙箱库"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

isolated-vm 中的严重漏洞允许沙箱化的 JavaScript 逃逸到主机，从而实现潜在的远程代码执行。所有版本直至 7.0.0 均受影响。

{{< cyber-report severity="Critical" source="The Hacker News" target="isolated-vm JavaScript 沙箱库" >}}

在 isolated-vm 中披露了一个严重的安全漏洞，这是一个广泛使用的开源 JavaScript 沙箱库，拥有超过 2900 个 GitHub 星标和 190 个分支。该漏洞被追踪为 GHSA-864f-rcv7-6rh4，允许攻击者逃逸沙箱环境，并可能在主机系统上执行任意代码。该库的所有版本直至并包括 7.0.0 均受影响。

{{< ad-banner >}}

该漏洞尤其令人担忧，因为 isolated-vm 旨在为运行不受信任的 JavaScript 代码提供安全边界。成功的沙箱逃逸可能会危及主机应用程序和底层基础设施。虽然尚未分配 CVE 标识符，但该公告强调使用此库的开发人员需要立即关注。

依赖 isolated-vm 的组织应监控补丁，并考虑缓解控制措施，例如限制不受信任代码的执行或应用额外的隔离层。目前缺乏 CVE 并不降低严重性，因为概念验证漏洞利用可能已经在安全社区中流传。

{{< netrunner-insight >}}

这次沙箱逃逸是一个鲜明的提醒，即使是专门构建的隔离工具也可能存在严重缺陷。SOC 分析师应对使用 isolated-vm 的任何应用程序进行清点，并在修复可用时优先进行修补。DevSecOps 团队还应审查其沙箱策略，并考虑纵深防御，例如在单独的容器或虚拟机中运行沙箱以限制爆炸半径。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html)**
