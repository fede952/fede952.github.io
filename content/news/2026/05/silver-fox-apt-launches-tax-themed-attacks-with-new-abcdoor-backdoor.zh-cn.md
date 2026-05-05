---
title: "Silver Fox APT组织发起以税务为主题的攻击，使用新型ABCDoor后门"
date: "2026-05-05T09:10:11Z"
original_date: "2026-05-04T14:39:26"
lang: "zh-cn"
translationKey: "silver-fox-apt-launches-tax-themed-attacks-with-new-abcdoor-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "中国支持的Silver Fox针对印度和俄罗斯发起税务主题钓鱼攻击，部署ABCDoor后门和ValleyRAT恶意软件。"
original_url: "https://www.darkreading.com/endpoint-security/silver-fox-tax-themed-attacks-india-russia"
source: "Dark Reading"
severity: "High"
target: "印度和俄罗斯的组织"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

中国支持的Silver Fox针对印度和俄罗斯发起税务主题钓鱼攻击，部署ABCDoor后门和ValleyRAT恶意软件。

{{< cyber-report severity="High" source="Dark Reading" target="印度和俄罗斯的组织" >}}

中国支持的APT组织Silver Fox发起了一场新活动，利用税务主题的社会工程学手段，针对印度和俄罗斯的组织。攻击涉及超过1600条社会工程学消息，针对多个行业，传播了包括ABCDoor后门和ValleyRAT在内的此前未记录的恶意软件。

{{< ad-banner >}}

ABCDoor后门是Silver Fox武器库中的新成员，旨在建立持久访问并窃取数据。ValleyRAT是一种已知的远程访问木马，也在这些攻击中被部署。该活动凸显了该组织持续关注金融和政府实体，利用时下税务主题提高受害者参与度。

安全研究人员敦促受影响地区的组织加强邮件过滤和用户意识培训，因为攻击严重依赖社会工程学。应监控与该活动相关的入侵指标（IOC），并更新网络防御以检测新的后门和RAT。

{{< netrunner-insight >}}

SOC分析师应优先监控税务主题的钓鱼邮件，并为ABCDoor后门的网络特征部署行为检测规则。DevSecOps团队必须确保端点检测和响应（EDR）工具已调整为识别ValleyRAT的持久化机制，并考虑阻止与Silver Fox相关的已知C2基础设施。

{{< /netrunner-insight >}}

---

**[在 Dark Reading 上阅读全文 ›](https://www.darkreading.com/endpoint-security/silver-fox-tax-themed-attacks-india-russia)**
