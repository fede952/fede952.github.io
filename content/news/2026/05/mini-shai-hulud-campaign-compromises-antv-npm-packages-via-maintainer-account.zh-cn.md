---
title: "Mini Shai-Hulud 活动通过维护者账户攻陷 @antv npm 包"
date: "2026-05-19T10:37:35Z"
original_date: "2026-05-19T04:54:17"
lang: "zh-cn"
translationKey: "mini-shai-hulud-campaign-compromises-antv-npm-packages-via-maintainer-account"
author: "NewsBot (Validated by Federico Sella)"
description: "攻击者入侵 @antv 维护者账户 'atool'，推送恶意 npm 包，包括周下载量达 110 万的 echarts-for-react，这是持续的 Mini Shai-Hulud 供应链攻击浪潮的一部分。"
original_url: "https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html"
source: "The Hacker News"
severity: "High"
target: "@antv npm 生态系统"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

攻击者入侵 @antv 维护者账户 'atool'，推送恶意 npm 包，包括周下载量达 110 万的 echarts-for-react，这是持续的 Mini Shai-Hulud 供应链攻击浪潮的一部分。

{{< cyber-report severity="High" source="The Hacker News" target="@antv npm 生态系统" >}}

网络安全研究人员发现了一起针对 @antv npm 生态系统的新型软件供应链攻击活动。攻击者入侵了 npm 维护者账户 'atool'，发布了多个包的恶意版本，其中包括 echarts-for-react，这是一个广泛使用的 Apache ECharts 的 React 封装，周下载量约 110 万。

{{< ad-banner >}}

该活动是持续的 Mini Shai-Hulud 攻击浪潮的一部分，此前该浪潮已针对其他开源生态系统。被攻陷的包可能包含恶意代码，旨在窃取敏感数据或在开发环境中建立后门。

使用任何 @antv 包的组织应立即审计其依赖项以寻找入侵迹象，轮换凭证，并审查其锁定文件中的近期更改。受影响包的完整范围和确切载荷仍在调查中。

{{< netrunner-insight >}}

此次攻击凸显了供应链安全措施的迫切需求，例如包完整性验证、维护者账户的多因素认证以及自动化依赖扫描。SOC 分析师应优先监控来自构建管道的异常出站流量，而 DevSecOps 团队必须对包发布账户实施严格的访问控制。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html)**
