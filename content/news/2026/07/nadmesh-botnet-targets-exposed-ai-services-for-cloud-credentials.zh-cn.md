---
title: "NadMesh僵尸网络瞄准暴露的AI服务以窃取云凭证"
date: "2026-07-19T09:05:56Z"
original_date: "2026-07-17T17:12:23"
lang: "zh-cn"
translationKey: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
slug: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "一个名为NadMesh的新型Go语言僵尸网络，专门搜寻暴露的AI平台（如ComfyUI和Ollama），窃取AWS密钥和Kubernetes令牌。据称已窃取超过3800个密钥。"
original_url: "https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html"
source: "The Hacker News"
severity: "High"
target: "暴露的AI服务（ComfyUI、Ollama、n8n等）"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

一个名为NadMesh的新型Go语言僵尸网络，专门搜寻暴露的AI平台（如ComfyUI和Ollama），窃取AWS密钥和Kubernetes令牌。据称已窃取超过3800个密钥。

{{< cyber-report severity="High" source="The Hacker News" target="暴露的AI服务（ComfyUI、Ollama、n8n等）" >}}

一个名为NadMesh的新型Go语言僵尸网络于2026年7月初出现，专门针对暴露的AI服务，窃取云凭证和Kubernetes令牌。该僵尸网络的操作面板显示已收集3811个唯一的AWS密钥，表明其运营规模相当可观。NadMesh使用基于Shodan的收割机不断填充其扫描队列，寻找流行AI工具（如ComfyUI、Ollama、n8n、Open WebUI、Langflow和Gradio）的易受攻击实例。

{{< ad-banner >}}

这些AI平台通常由开发团队快速部署，缺乏适当的安全加固，导致暴露在互联网上。该僵尸网络利用防火墙保护的缺失来获取访问权限并提取敏感凭证。对AI服务的关注表明攻击者的目标正在转向高价值的云基础设施和机器学习管道。

运行这些AI工具的组织应立即审计其暴露面，限制网络访问，并轮换可能已被泄露的任何凭证。NadMesh僵尸网络表明，错误配置的AI服务正成为凭证窃取和横向移动的主要目标，威胁形势日益严峻。

{{< netrunner-insight >}}

对于SOC分析师：优先扫描环境中暴露的ComfyUI、Ollama及类似AI服务。DevSecOps团队在部署这些工具前必须强制实施网络分段和防火墙规则。NadMesh僵尸网络清楚地提醒我们，未经安全审查的快速部署会招致自动化的凭证窃取。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html)**
