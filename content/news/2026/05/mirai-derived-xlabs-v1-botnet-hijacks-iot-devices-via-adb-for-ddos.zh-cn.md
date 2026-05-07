---
title: "源自Mirai的xlabs_v1僵尸网络通过ADB劫持物联网设备发起DDoS攻击"
date: "2026-05-07T09:27:29Z"
original_date: "2026-05-06T20:21:00"
lang: "zh-cn"
translationKey: "mirai-derived-xlabs-v1-botnet-hijacks-iot-devices-via-adb-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "研究人员发现xlabs_v1，一种基于Mirai的新型僵尸网络，利用暴露的Android调试桥端口将物联网设备招募到DDoS网络中。"
original_url: "https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html"
source: "The Hacker News"
severity: "High"
target: "暴露ADB的物联网设备"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究人员发现xlabs_v1，一种基于Mirai的新型僵尸网络，利用暴露的Android调试桥端口将物联网设备招募到DDoS网络中。

{{< cyber-report severity="High" source="The Hacker News" target="暴露ADB的物联网设备" >}}

网络安全研究人员发现了一种新的源自Mirai的僵尸网络，自称为xlabs_v1，它针对运行Android调试桥（ADB）的互联网暴露设备。该僵尸网络旨在将被入侵的设备纳入能够发起分布式拒绝服务（DDoS）攻击的网络中。

{{< ad-banner >}}

该发现由Hunt.io在识别出荷兰一台服务器上的暴露目录后做出。该恶意软件利用ADB（一种用于调试Android设备的命令行工具），该工具经常在物联网设备上暴露，使远程攻击者能够获得未经授权的访问。

此次攻击活动凸显了针对安全性较差的物联网设备的Mirai变种持续存在的威胁。建议组织在生产设备上禁用ADB，并限制网络访问以防止此类劫持。

{{< netrunner-insight >}}

对于SOC分析师，请监控来自外部IP的意外ADB连接。DevSecOps团队应确保在生产构建中禁用ADB，并将物联网设备与关键网络隔离，以减轻此僵尸网络的威胁。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html)**
