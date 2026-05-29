---
title: "XCharge C6电动汽车充电桩关键漏洞允许远程代码执行"
date: "2026-05-29T10:39:44Z"
original_date: "2026-05-28T12:00:00"
lang: "zh-cn"
translationKey: "critical-flaws-in-xcharge-c6-ev-charger-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA警告XCharge C6电动汽车充电控制器存在未认证漏洞，包括CVE-2026-9037，CVSS评分9.8。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08"
source: "CISA"
severity: "Critical"
target: "XCharge C6电动汽车充电控制器"
cve: "CVE-2026-9037"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA警告XCharge C6电动汽车充电控制器存在未认证漏洞，包括CVE-2026-9037，CVSS评分9.8。

{{< cyber-report severity="Critical" source="CISA" target="XCharge C6电动汽车充电控制器" cve="CVE-2026-9037" cvss="9.8" >}}

CISA已发布公告（ICSA-26-148-08），详细说明了XCharge C6电动汽车充电控制器中的多个关键漏洞。这些漏洞包括未进行完整性检查的代码下载（CWE-494）、基于栈的缓冲区溢出以及使用不安全默认值初始化资源。成功利用这些漏洞可能允许攻击者获得管理员权限或在设备上执行任意代码。

{{< ad-banner >}}

最严重的漏洞CVE-2026-9037涉及固件更新机制未能验证固件包的真实性。由于缺乏加密签名验证，能够干扰或冒充管理通道的攻击者可以安装未经授权的固件，从而导致高权限代码执行。该漏洞的CVSS v3评分为9.8，表明严重程度为关键。

XCharge已于2026年5月22日为所有受影响的充电桩部署了固件更新。建议用户确保设备已更新，并在需要时联系XCharge支持。受影响产品在多个国家的交通系统领域广泛部署。

{{< netrunner-insight >}}

对于SOC分析师，优先监控XCharge C6充电桩的管理接口，以发现未经授权的访问或异常的固件更新请求。DevSecOps团队应立即实施网络隔离并应用供应商补丁，因为缺乏完整性检查使得这些设备成为供应链攻击的主要目标。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08)**
