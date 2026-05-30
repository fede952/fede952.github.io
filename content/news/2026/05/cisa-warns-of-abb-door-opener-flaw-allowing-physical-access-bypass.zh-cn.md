---
title: "CISA警告ABB开门器漏洞可绕过物理访问控制"
date: "2026-05-30T09:11:24Z"
original_date: "2026-05-28T12:00:00"
lang: "zh-cn"
translationKey: "cisa-warns-of-abb-door-opener-flaw-allowing-physical-access-bypass"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA公告ICSA-26-148-04详细描述了ABB Busch-Welcome 2线开门器执行器中的一个身份验证绕过漏洞（CVE-2025-7705），该漏洞可导致未经授权的建筑访问。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04"
source: "CISA"
severity: "Medium"
target: "ABB Busch-Welcome 2线开门器执行器"
cve: "CVE-2025-7705"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA公告ICSA-26-148-04详细描述了ABB Busch-Welcome 2线开门器执行器中的一个身份验证绕过漏洞（CVE-2025-7705），该漏洞可导致未经授权的建筑访问。

{{< cyber-report severity="Medium" source="CISA" target="ABB Busch-Welcome 2线开门器执行器" cve="CVE-2025-7705" cvss="6.8" >}}

CISA发布了关于ABB Busch-Welcome 2线开门器执行器中身份验证绕过漏洞的公告ICSA-26-148-04，该漏洞编号为CVE-2025-7705。该缺陷源于默认启用的兼容模式，允许攻击者在安装受影响产品的建筑物中获得物理上的未经授权访问。该漏洞影响Switch Actuator 4 DU以及Switch actuator, door/light 4 DU的所有版本。

{{< ad-banner >}}

该漏洞的CVSS v3基础评分为6.8，属于中等严重性。ABB提供了修复步骤，包括切换产品上的模式开关并执行电源重置以重新校准系统。该产品部署在全球范围内，主要用于商业设施，供应商总部位于瑞士。

使用受影响ABB Busch-Welcome系统的组织应立即应用推荐的缓解措施。鉴于物理安全影响，该漏洞对建筑访问控制构成重大风险。安全团队应验证重新校准步骤是否正确执行，并监控任何利用迹象。

{{< netrunner-insight >}}

此漏洞鲜明地提醒我们，物联网和楼宇自动化设备通常默认存在不安全的配置。SOC分析师应优先对ABB Busch-Welcome系统进行资产发现，并确保应用手动重新校准。DevSecOps团队必须倡导安全设计原则，尤其是对于控制物理访问的设备。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04)**
