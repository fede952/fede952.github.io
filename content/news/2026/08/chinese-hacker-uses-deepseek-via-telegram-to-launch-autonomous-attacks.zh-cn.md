---
title: "中国黑客通过Telegram利用DeepSeek发起自主攻击"
date: "2026-08-01T09:07:32Z"
original_date: "2026-07-31T11:21:27"
lang: "zh-cn"
translationKey: "chinese-hacker-uses-deepseek-via-telegram-to-launch-autonomous-attacks"
slug: "chinese-hacker-uses-deepseek-via-telegram-to-launch-autonomous-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "Unit 42报告称，一名中文威胁行为者通过Hermes Agent利用DeepSeek，在收到一条Telegram命令后，对互联网暴露系统发起自主攻击。"
original_url: "https://thehackernews.com/2026/07/chinese-hacker-commands-deepseek-via.html"
source: "The Hacker News"
severity: "High"
target: "互联网暴露系统"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Unit 42报告称，一名中文威胁行为者通过Hermes Agent利用DeepSeek，在收到一条Telegram命令后，对互联网暴露系统发起自主攻击。

{{< cyber-report severity="High" source="The Hacker News" target="互联网暴露系统" >}}

Palo Alto Networks的Unit 42披露了一种新型攻击链，其中一名以knaithe和KnYuan为别名追踪的中文威胁行为者，通过开源Hermes Agent框架利用DeepSeek AI模型进行自主攻击。该行动始于一条Telegram指令，之后该代理独立识别互联网暴露系统并选择合适的公开漏洞利用。

{{< ad-banner >}}

据研究人员称，在会话期间未发现进一步的运营者输入，表明自动化程度很高。这标志着AI辅助网络攻击的重大演变，AI代理无需持续的人工指导即可处理侦察、漏洞利用选择和执行。

这些发现凸显了AI驱动的自主攻击工具日益增长的威胁，这些工具降低了技术水平较低的攻击者的门槛，并提高了操作的速度和规模。组织必须调整其防御措施，以应对此类自动化威胁，这些威胁可以以机器速度运行并适应其环境。

{{< netrunner-insight >}}

此事件凸显了SOC迫切需要监控AI驱动的攻击模式，例如可能缺乏典型人为错误特征的快速自动化利用尝试。DevSecOps团队应优先加固互联网暴露资产，并实施自动化检测和响应机制以应对自主威胁。此外，考虑限制AI模型访问并监控异常的API使用情况，这可能表明存在AI辅助攻击。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/chinese-hacker-commands-deepseek-via.html)**
