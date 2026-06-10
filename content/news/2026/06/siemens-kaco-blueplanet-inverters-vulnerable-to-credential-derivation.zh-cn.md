---
title: "西门子KACO Blueplanet逆变器存在凭证推导漏洞"
date: "2026-06-10T10:51:15Z"
original_date: "2026-06-09T12:00:00"
lang: "zh-cn"
translationKey: "siemens-kaco-blueplanet-inverters-vulnerable-to-credential-derivation"
author: "NewsBot (Validated by Federico Sella)"
description: "KACO blueplanet逆变器的多个漏洞允许攻击者从序列号推导出凭证，从而获得未授权访问。西门子建议进行更新。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02"
source: "CISA"
severity: "High"
target: "Siemens KACO Blueplanet Inverters"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

KACO blueplanet逆变器的多个漏洞允许攻击者从序列号推导出凭证，从而获得未授权访问。西门子建议进行更新。

{{< cyber-report severity="High" source="CISA" target="Siemens KACO Blueplanet Inverters" >}}

CISA发布了一份安全公告（ICSA-26-160-02），详细说明了西门子KACO blueplanet逆变器的多个漏洞。这些缺陷可能允许攻击者从设备的序列号推导出凭证，并滥用这些凭证获得对逆变器的未授权访问。

{{< ad-banner >}}

该公告涵盖了广泛的受影响型号，包括blueplanet 100 NX3 M8、100 TL3 GEN2、105 TL3等，版本列示为all/*或低于6.1.4.9的特定固件版本。KACO new energy GmbH已为部分产品发布了更新，并正在为其他产品准备修复方案，同时建议在补丁尚未可用的情况下采取缓解措施。

公告中未提供CVE标识符或CVSS评分。这些漏洞被认为严重，因为可能被远程利用导致未授权设备访问，进而影响太阳能基础设施。

{{< netrunner-insight >}}

对于SOC分析师和DevSecOps工程师，此安全公告强调了物联网/运营技术设备中硬编码或可推导凭证的风险。立即清查受影响的KACO逆变器，并在可用时应用固件更新。对于未修补的设备，实施网络分段并监控异常访问尝试作为临时缓解措施。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02)**
