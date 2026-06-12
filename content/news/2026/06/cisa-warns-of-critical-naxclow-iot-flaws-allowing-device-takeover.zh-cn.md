---
title: "CISA警告：Naxclow IoT严重漏洞可致设备被接管"
date: "2026-06-12T10:59:58Z"
original_date: "2026-06-11T12:00:00"
lang: "zh-cn"
translationKey: "cisa-warns-of-critical-naxclow-iot-flaws-allowing-device-takeover"
author: "NewsBot (Validated by Federico Sella)"
description: "Naxclow IoT平台存在多个漏洞（包括CVE-2026-42947），可导致设备劫持和凭证窃取。影响智能门铃和家庭中枢设备。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02"
source: "CISA"
severity: "Critical"
target: "Naxclow IoT平台设备"
cve: "CVE-2026-42947"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Naxclow IoT平台存在多个漏洞（包括CVE-2026-42947），可导致设备劫持和凭证窃取。影响智能门铃和家庭中枢设备。

{{< cyber-report severity="Critical" source="CISA" target="Naxclow IoT平台设备" cve="CVE-2026-42947" cvss="9.8" >}}

CISA发布了安全公告（ICSA-26-162-02），详细说明了Naxclow IoT平台中的多个漏洞，影响产品包括Smart Doorbell X3、X Smart Home、V720和ix cam。其中最严重的漏洞CVE-2026-42947的CVSS评分为9.8，涉及通过用户控制的密钥绕过授权，攻击者可重放“确认后绑定”序列，在无需用户交互的情况下将设备静默重新分配给任意账户。

{{< ad-banner >}}

其他弱点包括缺少授权检查、使用硬编码加密密钥、生成可预测标识符以及将敏感信息插入外部可访问文件。成功利用这些漏洞可能导致设备冒充、通信拦截或篡改、大规模凭证窃取以及对受影响系统的未授权访问。

这些漏洞影响所列产品的所有版本，且这些设备已部署在全球范围内的商业设施中。总部位于中国的Naxclow尚未发布补丁。使用这些设备的组织应立即实施网络分段和监控，以检测异常的设备绑定活动。

{{< netrunner-insight >}}

这是一个典型的供应链物联网噩梦：硬编码密钥、可预测的ID以及可重放的绑定流程。安全运营中心团队应在日志中寻找意外的设备重新分配，并考虑将Naxclow设备隔离到单独的VLAN中，直到补丁发布。开发安全运维必须推动在物联网绑定过程中使用加密设备身份和相互认证。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02)**
