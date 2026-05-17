---
title: "CISA警告：Siemens Opcenter RDnL存在ActiveMQ Artemis缺失认证漏洞"
date: "2026-05-17T08:59:55Z"
original_date: "2026-05-14T12:00:00"
lang: "zh-cn"
translationKey: "cisa-warns-of-siemens-opcenter-rdnl-flaw-via-activemq-artemis-missing-auth"
author: "NewsBot (Validated by Federico Sella)"
description: "Siemens Opcenter RDnL受CVE-2026-27446影响，该漏洞是ActiveMQ Artemis中的缺失认证漏洞，允许未认证的相邻攻击者注入或窃取消息。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09"
source: "CISA"
severity: "High"
target: "Siemens Opcenter RDnL"
cve: "CVE-2026-27446"
cvss: 7.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Siemens Opcenter RDnL受CVE-2026-27446影响，该漏洞是ActiveMQ Artemis中的缺失认证漏洞，允许未认证的相邻攻击者注入或窃取消息。

{{< cyber-report severity="High" source="CISA" target="Siemens Opcenter RDnL" cve="CVE-2026-27446" cvss="7.1" >}}

CISA发布了一份公告（ICSA-26-134-09），详细说明了Apache ActiveMQ Artemis中存在的关键功能缺失认证漏洞，该漏洞影响Siemens Opcenter RDnL。此漏洞编号为CVE-2026-27446，CVSS v3评分为7.1，允许相邻网络内的未认证攻击者强制目标代理与恶意代理建立出站Core联盟连接。这可能导致通过恶意代理向任何队列注入消息或从任何队列窃取消息。

{{< ad-banner >}}

该漏洞影响所有版本的Siemens Opcenter RDnL。由于缺少自动刷新功能且消息中不包含机密信息，完整性影响被认为较低，但可用性影响和消息篡改的可能性仍然显著。ActiveMQ Artemis已发布修复程序，Siemens建议立即更新至最新版本。

鉴于该产品在全球关键制造领域的部署，使用Opcenter RDnL的组织应优先进行修补。相邻网络攻击向量降低了直接暴露风险，但在分段环境中仍构成威胁。蓝队应监控异常的Core联盟连接和恶意代理活动。

{{< netrunner-insight >}}

对于SOC分析师，应监控来自ActiveMQ Artemis代理的意外出站Core联盟连接，这是被利用的主要指标。DevSecOps团队应立即更新至最新的ActiveMQ Artemis版本，并仅允许Core协议访问受信任的网络。此漏洞凸显了中间件组件中缺失认证的风险，即使直接影响看似较低。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09)**
