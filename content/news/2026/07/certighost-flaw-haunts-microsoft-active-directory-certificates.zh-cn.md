---
title: "“Certighost”漏洞困扰微软Active Directory证书"
date: "2026-07-29T09:36:19Z"
original_date: "2026-07-28T16:38:48"
lang: "zh-cn"
translationKey: "certighost-flaw-haunts-microsoft-active-directory-certificates"
slug: "certighost-flaw-haunts-microsoft-active-directory-certificates"
author: "NewsBot (Validated by Federico Sella)"
description: "微软修补了一个高危漏洞，该漏洞允许在Active Directory环境中进行权限提升。SOC分析师应优先进行修补。"
original_url: "https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates"
source: "Dark Reading"
severity: "High"
target: "Microsoft Active Directory Certificate Services"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

微软修补了一个高危漏洞，该漏洞允许在Active Directory环境中进行权限提升。SOC分析师应优先进行修补。

{{< cyber-report severity="High" source="Dark Reading" target="Microsoft Active Directory Certificate Services" >}}

微软修补了Active Directory证书服务中的一个高危漏洞，该漏洞被命名为“Certighost”，可能允许攻击者提升权限并危及Active Directory环境。该漏洞由Dark Reading于2026年7月28日披露。

{{< ad-banner >}}

该漏洞影响证书注册过程，使具有低级别访问权限的威胁行为者能够将其权限提升至域管理员。这可能导致AD基础设施完全受损，包括能够伪造证书并冒充任何用户或设备。

使用Microsoft Active Directory Certificate Services的组织应立即应用最新的安全更新。该漏洞凸显了证书服务在维护AD环境信任中的关键性质。

{{< netrunner-insight >}}

这是一个典型的AD证书服务攻击向量。确保证书模板已加固，并且注册权限受到严格控制。立即修补，并监控异常的证书请求或权限提升。

{{< /netrunner-insight >}}

---

**[在 Dark Reading 上阅读全文 ›](https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates)**
