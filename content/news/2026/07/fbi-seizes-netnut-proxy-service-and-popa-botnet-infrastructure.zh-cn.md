---
title: "FBI查封NetNut代理服务及Popa僵尸网络基础设施"
date: "2026-07-04T09:20:04Z"
original_date: "2026-07-02T19:27:33"
lang: "zh-cn"
translationKey: "fbi-seizes-netnut-proxy-service-and-popa-botnet-infrastructure"
author: "NewsBot (Validated by Federico Sella)"
description: "FBI已查封与NetNut相关的域名，NetNut是一个住宅代理服务，与由200万台受感染设备组成的Popa僵尸网络有关联，此次行动基于调查报道。"
original_url: "https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/"
source: "Krebs on Security"
severity: "High"
target: "住宅代理服务NetNut及Popa僵尸网络"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

FBI已查封与NetNut相关的域名，NetNut是一个住宅代理服务，与由200万台受感染设备组成的Popa僵尸网络有关联，此次行动基于调查报道。

{{< cyber-report severity="High" source="Krebs on Security" target="住宅代理服务NetNut及Popa僵尸网络" >}}

FBI与行业合作伙伴协调，查封了与NetNut相关的数百个域名。NetNut是一家住宅代理服务，由上市公司以色列Alarum Technologies（纳斯达克：ALAR）运营。此次行动源于KrebsOnSecurity的一篇报道，该报道将NetNut与Popa僵尸网络联系起来，后者是一个由至少200万台未经用户同意而被感染的设备组成的网络。

{{< ad-banner >}}

Popa僵尸网络利用受感染设备通过NetNut的代理基础设施路由流量，从而实施凭证填充、广告欺诈和账户接管等恶意活动。此次查封同时破坏了代理服务和僵尸网络的命令与控制能力。

此次行动凸显了执法部门针对助长网络犯罪的代理服务的日益增长的趋势。组织应审查其网络流量中是否存在与已查封域名的连接，并监控残留的僵尸网络活动。

{{< netrunner-insight >}}

对于SOC分析师而言，此次取缔行动强调了在威胁情报源中监控住宅代理IP范围的重要性。DevSecOps团队应审计与第三方代理服务的任何集成，并确保部署强大的僵尸网络检测机制，因为Popa的残余部分可能在其他基础设施中持续存在。

{{< /netrunner-insight >}}

---

**[在 Krebs on Security 上阅读全文 ›](https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/)**
