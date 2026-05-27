---
title: "CISA警告：ABB Camera Connect因VLC媒体播放器组件存在漏洞"
date: "2026-05-27T10:51:57Z"
original_date: "2026-05-26T12:00:00"
lang: "zh-cn"
translationKey: "cisa-warns-of-abb-camera-connect-flaws-via-vlc-media-player-component"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB Ability Camera Connect版本≤1.5.0.14包含易受攻击的VLC媒体播放器2.2.4，存在多个内存损坏漏洞，包括CVE-2024-46461，构成严重风险。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05"
source: "CISA"
severity: "Critical"
target: "ABB Ability Camera Connect"
cve: "CVE-2024-46461"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB Ability Camera Connect版本≤1.5.0.14包含易受攻击的VLC媒体播放器2.2.4，存在多个内存损坏漏洞，包括CVE-2024-46461，构成严重风险。

{{< cyber-report severity="Critical" source="CISA" target="ABB Ability Camera Connect" cve="CVE-2024-46461" cvss="9.8" >}}

CISA发布了一份公告（ICSA-26-146-05），详细说明了ABB Ability Camera Connect 1.5.0.14及以下版本中的多个漏洞。这些漏洞源于过时的第三方组件VLC媒体播放器2.2.4，该组件随安装包捆绑提供。升级到1.5.0.15版本可通过替换易受攻击的组件来解决此问题。

{{< ad-banner >}}

这些漏洞包括基于堆的缓冲区溢出、整数下溢、越界写入、不受控制的搜索路径元素、整数溢出、差一错误、越界读取、双重释放、内存缓冲区操作限制不当以及释放后使用。值得注意的是，CVE-2024-46461描述了VLC媒体播放器3.0.20及更早版本中通过恶意构造的MMS流导致的基于堆的溢出，从而导致拒绝服务。

这些漏洞的CVSS v3评分为9.8，被评为严重级别。受影响的关键基础设施领域包括化工、商业设施、通信、关键制造、能源和运输系统。该产品在全球范围内部署，利用这些漏洞可能使攻击者以多种方式危害系统。

{{< netrunner-insight >}}

此公告强调了第三方组件继承漏洞的风险。SOC分析师应优先将ABB Ability Camera Connect升级到1.5.0.15版本，并监控针对VLC媒体播放器漏洞的利用尝试。DevSecOps团队必须严格执行组件版本控制，并定期扫描捆绑的库。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05)**
