---
title: "OpenAI Codex 认证令牌在 npm 供应链攻击中被窃取"
date: "2026-06-01T12:34:23Z"
original_date: "2026-06-01T09:31:15"
lang: "zh-cn"
translationKey: "openai-codex-auth-tokens-stolen-in-npm-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "恶意 npm 包 codexui-android 针对开发者，窃取 OpenAI Codex 认证令牌，每周下载量超过 29,000 次。"
original_url: "https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html"
source: "The Hacker News"
severity: "High"
target: "OpenAI Codex 开发者"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

恶意 npm 包 codexui-android 针对开发者，窃取 OpenAI Codex 认证令牌，每周下载量超过 29,000 次。

{{< cyber-report severity="High" source="The Hacker News" target="OpenAI Codex 开发者" >}}

网络安全研究人员发现了一场针对使用 OpenAI Codex 的开发者的恶意供应链攻击活动。该攻击利用了一个看似合法的 npm 包 codexui-android，该包在 GitHub 和 npm 上被宣传为 OpenAI Codex 的远程 Web 界面。该包已吸引超过 29,000 次每周下载，表明其在开发者社区中的广泛影响。

{{< ad-banner >}}

该恶意包旨在从毫无戒心的开发者那里窃取 OpenAI Codex 认证令牌。截至报告发布时，该包仍可下载，构成持续威胁。建议已安装 codexui-android 的开发者立即轮换其令牌，并审计系统是否存在未经授权的访问。

此事件凸显了开源生态系统中供应链攻击的持续风险。使用听起来合法的包名和高下载量可能会让开发者产生虚假的安全感。组织应实施严格的包审查流程，并考虑使用检测异常包行为的工具。

{{< netrunner-insight >}}

对于 SOC 分析师和 DevSecOps 工程师而言，此次攻击强调了监控 npm 包下载和行为的重要性。实施运行时检测以发现意外的令牌外泄，并对 API 令牌强制执行最小权限访问。定期审计软件供应链，并考虑使用包完整性验证工具。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html)**
