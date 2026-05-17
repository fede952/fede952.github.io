---
title: "西门子Ruggedcom ROX漏洞允许通过参数注入实现根文件读取"
date: "2026-05-17T09:01:07Z"
original_date: "2026-05-14T12:00:00"
lang: "zh-cn"
translationKey: "siemens-ruggedcom-rox-flaw-allows-root-file-read-via-argument-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA警告CVE-2025-40948影响多个Ruggedcom ROX设备。经过身份验证的远程攻击者可以读取任意文件并获得root权限。请更新至v2.17.1或更高版本。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02"
source: "CISA"
severity: "Medium"
target: "Siemens Ruggedcom ROX devices"
cve: "CVE-2025-40948"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA警告CVE-2025-40948影响多个Ruggedcom ROX设备。经过身份验证的远程攻击者可以读取任意文件并获得root权限。请更新至v2.17.1或更高版本。

{{< cyber-report severity="Medium" source="CISA" target="Siemens Ruggedcom ROX devices" cve="CVE-2025-40948" cvss="6.8" >}}

西门子Ruggedcom ROX系列设备存在不当访问控制漏洞（CVE-2025-40948），允许经过身份验证的远程攻击者以root权限从底层操作系统读取任意文件。该漏洞源于Web服务器JSON-RPC接口对输入验证不当，导致参数注入。

{{< ad-banner >}}

以下产品受影响：RUGGEDCOM ROX MX5000、MX5000RE、RX1400、RX1500、RX1501、RX1510、RX1511、RX1512、RX1524、RX1536和RX5000，所有版本均低于2.17.1。西门子已发布更新修复该问题，并建议立即修补。

该漏洞CVSS v3评分为6.8，评级为中等。攻击向量为网络，需要低权限，无需用户交互。鉴于这些设备部署在关键基础设施领域（如关键制造业），利用该漏洞可能导致重大信息泄露。

{{< netrunner-insight >}}

对于SOC分析师：优先修补环境中的Ruggedcom ROX设备，尤其是暴露在不可信网络中的设备。漏洞利用需要身份验证降低了即时风险，但并未消除——攻击者若攻破低权限账户，可升级为完全根文件访问。DevSecOps团队应审查JSON-RPC端点加固，并考虑网络分段以限制暴露。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02)**
