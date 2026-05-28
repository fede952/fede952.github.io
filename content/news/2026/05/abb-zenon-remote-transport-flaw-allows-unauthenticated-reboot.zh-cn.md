---
title: "ABB Zenon远程传输漏洞允许未经身份验证的重启"
date: "2026-05-28T10:50:49Z"
original_date: "2026-05-26T12:00:00"
lang: "zh-cn"
translationKey: "abb-zenon-remote-transport-flaw-allows-unauthenticated-reboot"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA警告ABB Ability Zenon中的CVE-2025-8754漏洞，可通过远程传输服务实现未经授权的系统重启。目前未发现活跃利用。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03"
source: "CISA"
severity: "High"
target: "ABB Ability Zenon系统"
cve: "CVE-2025-8754"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA警告ABB Ability Zenon中的CVE-2025-8754漏洞，可通过远程传输服务实现未经授权的系统重启。目前未发现活跃利用。

{{< cyber-report severity="High" source="CISA" target="ABB Ability Zenon系统" cve="CVE-2025-8754" cvss="7.5" >}}

CISA发布了一份公告（ICSA-26-146-03），详细说明了ABB Ability Zenon远程传输服务中缺少身份验证的漏洞。该漏洞编号为CVE-2025-8754，CVSS评分为7.5，允许攻击者在没有正确凭据的情况下触发系统重启。受影响的版本范围从7.50到14。

{{< ad-banner >}}

利用该漏洞需要事先获得网络访问权限，因为攻击者必须与目标Zenon系统处于同一网络中。ABB指出，在默认配置下，zensyssrv.exe服务会自动启动，但用户必须配置密码才能使用远程传输服务。截至本文撰写时，尚未发现野外活跃利用的证据。

该公告强调了ABB Ability Zenon在全球关键基础设施领域的广泛部署，包括化工、能源、医疗保健以及水和废水处理系统。使用受影响版本的组织应立即应用ABB提供的缓解措施或更新，以防止潜在的拒绝服务攻击。

{{< netrunner-insight >}}

对于SOC分析师：优先进行网络分段以限制Zenon系统的暴露，并确保远程传输服务的密码已配置且强度足够。DevSecOps团队应验证zensyssrv.exe服务未暴露给不可信网络，并在供应商补丁可用时立即应用。鉴于CVSS 7.5评分和对关键基础设施的影响，即使没有活跃利用，也应将此视为高优先级发现。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03)**
