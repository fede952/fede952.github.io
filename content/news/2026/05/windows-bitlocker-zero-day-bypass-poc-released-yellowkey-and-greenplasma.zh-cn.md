---
title: "Windows BitLocker零日绕过PoC发布：YellowKey和GreenPlasma"
date: "2026-05-14T09:30:15Z"
original_date: "2026-05-13T16:37:49"
lang: "zh-cn"
translationKey: "windows-bitlocker-zero-day-bypass-poc-released-yellowkey-and-greenplasma"
author: "NewsBot (Validated by Federico Sella)"
description: "针对两个未修补的Windows漏洞——YellowKey（BitLocker绕过）和GreenPlasma（权限提升）的概念验证利用代码已公开，对加密驱动器构成风险。"
original_url: "https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/"
source: "BleepingComputer"
severity: "High"
target: "Windows BitLocker保护的驱动器"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

针对两个未修补的Windows漏洞——YellowKey（BitLocker绕过）和GreenPlasma（权限提升）的概念验证利用代码已公开，对加密驱动器构成风险。

{{< cyber-report severity="High" source="BleepingComputer" target="Windows BitLocker保护的驱动器" >}}

一名网络安全研究员发布了针对两个未修补的Microsoft Windows漏洞的概念验证（PoC）利用代码，这两个漏洞分别被称为YellowKey和GreenPlasma。YellowKey是一个BitLocker绕过漏洞，允许攻击者在没有正确身份验证的情况下访问受保护驱动器上的数据；而GreenPlasma是一个权限提升漏洞，可能使攻击者在受感染系统上获得提升的权限。

{{< ad-banner >}}

这些PoC的发布增加了被利用的风险，因为威胁行为者现在可以将这些技术武器化。依赖BitLocker进行全盘加密的组织应评估其暴露风险，并考虑额外的安全控制措施，例如启用TPM+PIN保护或使用预启动身份验证。

Microsoft尚未发布针对这些漏洞的补丁，因此在修复程序部署之前，系统仍处于暴露状态。安全团队应监控对加密驱动器的异常访问模式，并在可能的情况下应用变通方案，例如禁用不必要的启动选项或强制执行强PIN策略。

{{< netrunner-insight >}}

对于SOC分析师，优先监控对BitLocker保护驱动器的未授权访问尝试和权限提升事件。DevSecOps工程师应针对已发布的PoC测试其环境，以识别易受攻击的配置，并实施补偿控制措施，如安全启动和测量启动日志。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)**
