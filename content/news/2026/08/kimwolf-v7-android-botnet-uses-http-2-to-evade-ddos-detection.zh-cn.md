---
title: "Kimwolf v7 Android僵尸网络利用HTTP/2规避DDoS检测"
date: "2026-08-16T07:27:33Z"
original_date: "2026-08-11T19:36:37"
lang: "zh-cn"
translationKey: "kimwolf-v7-android-botnet-uses-http-2-to-evade-ddos-detection"
slug: "kimwolf-v7-android-botnet-uses-http-2-to-evade-ddos-detection"
author: "NewsBot (Validated by Federico Sella)"
description: "Unit 42发现的新Kimwolf v7 Android和物联网僵尸网络利用HTTP/2使DDoS流量看起来像合法浏览，提高了韧性。"
original_url: "https://thehackernews.com/2026/08/kimwolf-v7-android-botnet-makes-http2.html"
source: "The Hacker News"
severity: "Medium"
target: "Android和物联网设备"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Unit 42发现的新Kimwolf v7 Android和物联网僵尸网络利用HTTP/2使DDoS流量看起来像合法浏览，提高了韧性。

{{< cyber-report severity="Medium" source="The Hacker News" target="Android和物联网设备" >}}

网络安全研究人员发现了一个新版本的Kimwolf/AISURU僵尸网络，命名为Kimwolf v7，它针对Android和物联网（IoT）设备。该变种由Palo Alto Networks Unit 42于2026年2月识别，并引入了旨在提高运营韧性和执行分布式拒绝服务（DDoS）攻击的重大增强功能。

{{< ad-banner >}}

Kimwolf v7的一个关键改进是采用基于HTTP/2的流量，这使得僵尸网络能够使其DDoS攻击流量看起来像合法的浏览活动。该技术旨在规避可能无法有效区分恶意和良性HTTP/2流量的安全解决方案的检测，从而增加了缓解此类攻击的难度。

这一发现凸显了僵尸网络运营者日益复杂的演变，他们不断调整工具以绕过现代安全防御。网络中拥有Android和物联网设备的组织应意识到这一威胁，并考虑更新其检测机制以应对基于HTTP/2的异常。

{{< netrunner-insight >}}

对于SOC分析师来说，这强调了需要对正常的HTTP/2流量模式进行基线化，并部署行为分析，以便即使在流量看似合法时也能发现异常。DevSecOps团队应确保DDoS缓解解决方案能够检查HTTP/2流量，并考虑在应用层实施速率限制和异常检测，以应对此类规避技术。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/kimwolf-v7-android-botnet-makes-http2.html)**
