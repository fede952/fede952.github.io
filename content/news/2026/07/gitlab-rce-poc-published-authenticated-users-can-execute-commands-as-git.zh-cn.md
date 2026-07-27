---
title: "GitLab RCE PoC已发布：认证用户可作为Git用户执行命令"
date: "2026-07-27T10:37:15Z"
original_date: "2026-07-25T10:14:26"
lang: "zh-cn"
translationKey: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
slug: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
author: "NewsBot (Validated by Federico Sella)"
description: "针对GitLab远程代码执行漏洞的概念验证利用代码已发布，目标为未打补丁的18.11.3自管理服务器。认证用户可作为git用户运行命令。"
original_url: "https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html"
source: "The Hacker News"
severity: "High"
target: "GitLab自管理18.11.3"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

针对GitLab远程代码执行漏洞的概念验证利用代码已发布，目标为未打补丁的18.11.3自管理服务器。认证用户可作为git用户运行命令。

{{< cyber-report severity="High" source="The Hacker News" target="GitLab自管理18.11.3" >}}

2026年7月24日，depthfirst的安全研究人员发布了针对GitLab远程代码执行漏洞的有效概念验证利用代码。该漏洞于2026年6月10日被GitLab修复，允许任何对项目具有推送权限的认证用户在未应用更新的自管理GitLab 18.11.3服务器上以git用户身份执行任意命令。

{{< ad-banner >}}

该利用代码利用提交到项目中的精心构造的Jupyter笔记本。当攻击者打开提交差异时，恶意笔记本触发堆泄漏，从而实现命令执行。此技术绕过了典型的认证控制，除了标准项目访问权限外不需要特殊权限。

运行自管理GitLab实例的组织应立即确认已应用6月10日的补丁。利用代码的公开可用性增加了主动利用的风险，尤其是对于暴露在互联网上的实例。蓝队应监控异常的Jupyter笔记本提交和意外的git用户活动。

{{< netrunner-insight >}}

此利用代码凸显了自管理CI/CD平台中延迟修补的危险。SOC分析师应优先检测异常的git用户进程和意外的Jupyter笔记本上传。DevSecOps团队必须为GitLab强制执行严格的补丁窗口，并考虑网络分段以限制自管理实例的暴露。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)**
