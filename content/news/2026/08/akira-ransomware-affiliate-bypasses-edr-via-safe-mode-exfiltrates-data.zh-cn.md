---
title: "Akira勒索软件关联方通过安全模式绕过EDR并窃取数据"
date: "2026-08-16T07:35:41Z"
original_date: "2026-08-13T20:47:02"
lang: "zh-cn"
translationKey: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
slug: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
author: "NewsBot (Validated by Federico Sella)"
description: "Akira勒索软件关联方通过带网络的安全模式启动来禁用EDR，窃取数据但未能加密。了解如何防御。"
original_url: "https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/"
source: "BleepingComputer"
severity: "High"
target: "端点检测与响应（EDR）解决方案"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Akira勒索软件关联方通过带网络的安全模式启动来禁用EDR，窃取数据但未能加密。了解如何防御。

{{< cyber-report severity="High" source="BleepingComputer" target="端点检测与响应（EDR）解决方案" >}}

已观察到Akira勒索软件关联方通过将受感染系统重启至带网络的安全模式来禁用端点检测与响应（EDR）解决方案。此技术允许攻击者在没有EDR监控的情况下操作，因为许多安全工具在安全模式下不会加载。

{{< ad-banner >}}

该关联方成功从受害者网络窃取了敏感数据，但攻击的加密阶段失败。这表明虽然EDR绕过有效，但其他安全控制或操作问题阻止了最终勒索软件有效载荷的正常执行。

此事件凸显了强化启动配置和监控意外系统重启（尤其是进入安全模式）的重要性。组织还应确保EDR解决方案启用了防篡改保护，并限制或监控安全模式启动。

{{< netrunner-insight >}}

对于SOC分析师来说，这提醒我们EDR绕过可能简单到只需重启进入安全模式。监控异常的关机/重启事件，并考虑通过BIOS/UEFI密码或组策略禁用安全模式启动。DevSecOps应确保EDR代理配置为在安全模式下启动，并强制执行防篡改保护，以防止这种常见的规避技术。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/)**
