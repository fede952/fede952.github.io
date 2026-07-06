---
title: "TrojPix攻击通过视频线缆辐射从气隙系统窃取数据"
date: "2026-07-06T11:24:53Z"
original_date: "2026-07-06T08:50:54"
lang: "zh-cn"
translationKey: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
slug: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
author: "NewsBot (Validated by Federico Sella)"
description: "研究人员演示了TrojPix技术，该技术通过调制屏幕像素使视频线缆发出微弱无线电信号，从而从气隙计算机泄露数据，但需要事先植入恶意软件。"
original_url: "https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html"
source: "The Hacker News"
severity: "Medium"
target: "气隙系统"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究人员演示了TrojPix技术，该技术通过调制屏幕像素使视频线缆发出微弱无线电信号，从而从气隙计算机泄露数据，但需要事先植入恶意软件。

{{< cyber-report severity="Medium" source="The Hacker News" target="气隙系统" >}}

山东大学的研究人员揭示了TrojPix，一种通过利用视频线缆的电磁辐射从气隙计算机窃取数据的新型攻击。该技术以人眼不可察觉的方式微妙地改变屏幕像素，导致视频线缆辐射出微弱的无线电信号，可被附近的接收器捕获和解码。

{{< ad-banner >}}

TrojPix需要在目标系统上预先安装恶意软件以操纵像素值。与以往的气隙隐蔽信道相比，这种方法实现了显著更高的数据传输速率，使其成为高度安全环境中的实际威胁。该攻击凸显了即使在物理隔离网络中保护数据的持续挑战。

尽管该技术复杂，但其对预先存在的恶意软件的依赖限制了其适用性。组织应通过强大的端点安全防护和监控敏感区域的异常电磁辐射，专注于防止初始入侵。

{{< netrunner-insight >}}

对于SOC分析师而言，TrojPix强调了气隙系统并非对数据窃取免疫。监控敏感工作站附近的异常电磁信号，并实施严格的物理安全措施。DevSecOps团队应考虑屏蔽视频线缆，并在可行的情况下实施像素级异常检测。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html)**
