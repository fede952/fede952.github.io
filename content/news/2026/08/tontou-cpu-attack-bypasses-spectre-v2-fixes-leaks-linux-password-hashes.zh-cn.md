---
title: "TONTOU CPU攻击绕过Spectre v2修复，泄露Linux密码哈希"
date: "2026-08-10T08:26:15Z"
original_date: "2026-08-06T18:03:45"
lang: "zh-cn"
translationKey: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
slug: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "研究人员开发出TONTOU攻击，绕过最近的Spectre v2缓解措施，成功泄露包括Linux系统密码哈希在内的机密信息。"
original_url: "https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/"
source: "BleepingComputer"
severity: "High"
target: "Linux系统"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究人员开发出TONTOU攻击，绕过最近的Spectre v2缓解措施，成功泄露包括Linux系统密码哈希在内的机密信息。

{{< cyber-report severity="High" source="BleepingComputer" target="Linux系统" >}}

安全研究人员揭示了一种名为TONTOU的新型推测执行攻击，该攻击绕过了针对Spectre v2漏洞的最新缓解措施。该攻击针对CPU的分支预测机制，这些机制此前已通过补丁防止侧信道泄露。通过利用这些防御中的漏洞，研究人员能够从Linux机器的内核内存中提取敏感数据。

{{< ad-banner >}}

概念验证利用通过成功泄露目标系统的密码哈希，展示了该问题的严重性。这表明该攻击可能被用来危及用户凭据并可能提升权限。这些发现凸显了完全缓解推测执行侧信道攻击的持续挑战，因为尽管有先前的修复，新的变体仍在不断出现。

虽然研究人员尚未发布完整的技术细节，但他们的工作强调了在CPU安全方面保持持续警惕的必要性。建议系统管理员关注CPU供应商和Linux发行版的更新，并考虑采取额外的加固措施，如内核地址空间布局随机化（KASLR）和微码更新。

{{< netrunner-insight >}}

这次攻击鲜明地提醒我们，推测执行漏洞尚未完全解决。SOC分析师应优先进行补丁更新，并监控任何利用迹象，而DevSecOps工程师应审查其威胁模型中的侧信道风险。鉴于可能泄露密码哈希，应立即关注Linux内核更新和CPU微码。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/)**
