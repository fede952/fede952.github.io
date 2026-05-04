---
title: "Ruby Gem 和 Go 模块中的休眠包瞄准 CI/CD 管道"
date: "2026-05-04T09:17:53Z"
original_date: "2026-05-01T09:43:00"
lang: "zh-cn"
translationKey: "sleeper-packages-in-ruby-gems-and-go-modules-target-ci-cd-pipelines"
author: "NewsBot (Validated by Federico Sella)"
description: "攻击者利用休眠包传递恶意负载，窃取凭证、篡改 GitHub Actions 并在软件供应链攻击中建立 SSH 持久化。"
original_url: "https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html"
source: "The Hacker News"
severity: "High"
target: "CI/CD 管道和软件供应链"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

攻击者利用休眠包传递恶意负载，窃取凭证、篡改 GitHub Actions 并在软件供应链攻击中建立 SSH 持久化。

{{< cyber-report severity="High" source="The Hacker News" target="CI/CD 管道和软件供应链" >}}

一项新的软件供应链攻击活动被发现使用休眠包作为渠道，随后推送恶意负载，实现凭证窃取、GitHub Actions 篡改和 SSH 持久化。该活动归因于 GitHub 账户 "BufferZoneCorp"，该账户发布了一系列与恶意 Ruby gem 和 Go 模块相关的仓库。

{{< ad-banner >}}

该攻击利用最初看似良性的包，随后接收恶意更新，这种技术被称为“休眠”或“木马化”包。一旦安装在 CI/CD 环境中，负载会窃取凭证、修改 GitHub Actions 工作流并建立持久的 SSH 访问，对开发管道构成重大威胁。

使用来自不可信来源的 Ruby gem 或 Go 模块的组织应审计其依赖项并监控可疑的仓库活动。该活动凸显了针对开发者基础设施的供应链攻击日益复杂化。

{{< netrunner-insight >}}

此活动强调了在 CI/CD 管道中严格依赖锁定和完整性验证的必要性。SOC 分析师应监控异常的 GitHub Actions 修改和 SSH 密钥添加，而 DevSecOps 工程师应实施最小权限访问，并考虑使用临时构建环境以限制爆炸半径。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html)**
