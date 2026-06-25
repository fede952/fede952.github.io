---
title: "Cordyceps CI/CD 漏洞威胁 300 多个 GitHub 仓库"
date: "2026-06-25T10:14:17Z"
original_date: "2026-06-24T12:48:11"
lang: "zh-cn"
translationKey: "cordyceps-ci-cd-flaws-threaten-300-github-repos"
author: "NewsBot (Validated by Federico Sella)"
description: "代号为 Cordyceps 的新型 CI/CD 工作流弱点允许攻击者劫持工作流，并危及主要组织的开源供应链。"
original_url: "https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html"
source: "The Hacker News"
severity: "Critical"
target: "GitHub 上的 CI/CD 工作流"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

代号为 Cordyceps 的新型 CI/CD 工作流弱点允许攻击者劫持工作流，并危及主要组织的开源供应链。

{{< cyber-report severity="Critical" source="The Hacker News" target="GitHub 上的 CI/CD 工作流" >}}

Novee Security 的网络安全研究人员发现了一种 CI/CD 工作流中可被利用的关键模式，命名为 Cordyceps，该模式允许攻击者劫持工作流并破坏开源供应链。该漏洞影响超过 300 个 GitHub 仓库，涉及包括 Microsoft、Google 和 Apache 在内的主要组织。

{{< ad-banner >}}

Cordyceps 模式使攻击者能够完全控制仓库，可能导致未经授权的代码更改、后门插入以及下游供应链攻击。该漏洞源于不安全的工流配置，未能正确隔离或验证输入。

使用 GitHub Actions 或类似 CI/CD 平台的组织被敦促检查其工作流定义是否存在 Cordyceps 模式，并实施最小权限原则、输入清理和环境隔离以降低风险。

{{< netrunner-insight >}}

这是一个典型的供应链攻击向量。SOC 分析师应监控异常的工作流执行和意外的仓库更改。DevSecOps 团队必须立即审计 CI/CD 管道配置，重点关注不可信输入处理和权限范围。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)**
