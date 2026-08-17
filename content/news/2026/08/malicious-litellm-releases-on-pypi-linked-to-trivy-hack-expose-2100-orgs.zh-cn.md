---
title: "PyPI上恶意LiteLLM发布与Trivy黑客攻击相关，暴露2100多个组织"
date: "2026-08-17T07:48:06Z"
original_date: "2026-08-12T08:04:52"
lang: "zh-cn"
translationKey: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
slug: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
author: "NewsBot (Validated by Federico Sella)"
description: "PyPI上的两个恶意LiteLLM包窃取了云密钥、SSH密钥等。CloudSEK数据表明，可能有超过2100个组织受到影响。"
original_url: "https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html"
source: "The Hacker News"
severity: "High"
target: "PyPI上的LiteLLM用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

PyPI上的两个恶意LiteLLM包窃取了云密钥、SSH密钥等。CloudSEK数据表明，可能有超过2100个组织受到影响。

{{< cyber-report severity="High" source="The Hacker News" target="PyPI上的LiteLLM用户" >}}

3月份，两个恶意LiteLLM版本发布在PyPI上，并持续了大约40分钟。这些包包含窃取凭据的代码，旨在从任何安装了它们的系统中收集各种机密信息，包括云访问密钥、SSH私钥、Kubernetes令牌和数据库密码。

{{< ad-banner >}}

威胁情报公司CloudSEK获取了一个数据集，该数据集由攻击者捕获的大约434,000个文件构建而成。对该数据集的分析表明，此次泄露可能影响超过2100个组织，凸显了潜在的攻击规模。

该事件与早前的Trivy黑客攻击有关，表明这是一次协同的供应链攻击。在受影响窗口期间从PyPI安装LiteLLM的组织应立即轮换所有暴露的凭据，并调查是否存在未经授权的访问迹象。

{{< netrunner-insight >}}

此事件凸显了对软件供应链保持警惕的迫切需求。SOC分析师应监控任何恶意LiteLLM版本的安装情况，并优先轮换可能暴露的机密信息。DevSecOps团队应实施严格的包完整性检查，并考虑使用私有镜像或带有哈希的锁文件来降低此类风险。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html)**
