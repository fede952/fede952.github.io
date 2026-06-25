---
title: "恶意Edge扩展'Edgecution'利用原生消息传递部署后门"
date: "2026-06-25T10:16:09Z"
original_date: "2026-06-24T20:58:22"
lang: "zh-cn"
translationKey: "malicious-edge-extension-edgecution-uses-native-messaging-to-deploy-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "一款名为'Edgecution'的恶意Microsoft Edge扩展通过原生消息传递逃逸浏览器沙箱，在勒索软件攻击中部署基于Python的后门。"
original_url: "https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/"
source: "BleepingComputer"
severity: "High"
target: "Microsoft Edge用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

一款名为'Edgecution'的恶意Microsoft Edge扩展通过原生消息传递逃逸浏览器沙箱，在勒索软件攻击中部署基于Python的后门。

{{< cyber-report severity="High" source="BleepingComputer" target="Microsoft Edge用户" >}}

一款名为'Edgecution'的恶意Microsoft Edge扩展已在勒索软件攻击中被发现，它利用浏览器的原生消息传递API逃逸沙箱，在主机系统上执行任意代码。该扩展充当桥梁，部署基于Python的后门，实现持久访问并进一步实施恶意活动。

{{< ad-banner >}}

攻击链始于安装恶意扩展，随后该扩展滥用原生消息传递与浏览器沙箱外的原生应用程序通信。此技术绕过了典型的浏览器安全边界，使攻击者能够执行命令并投放额外载荷，包括勒索软件。

安全研究人员强调，这种方法特别隐蔽，因为它利用了合法的浏览器功能，使得传统端点安全解决方案难以检测。建议组织监控未经授权的浏览器扩展，并尽可能限制原生消息传递权限。

{{< netrunner-insight >}}

此次攻击凸显了监控浏览器扩展安装和原生消息传递活动的重要性。SOC分析师应关注异常的扩展行为和意外的原生主机通信，而DevSecOps团队应实施严格的扩展白名单，并禁用不必要的原生消息传递主机。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)**
