---
title: "以SPID为主题的钓鱼活动瞄准意大利用户的凭据"
date: "2026-08-17T07:50:54Z"
original_date: "2026-08-03T11:05:05"
lang: "zh-cn"
translationKey: "spid-themed-phishing-campaign-targets-italian-users-credentials"
slug: "spid-themed-phishing-campaign-targets-italian-users-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-AGID警告称，一场新的钓鱼活动滥用SPID和AgID品牌，通过包含“spid”和“gov”的域名窃取个人和银行数据。"
original_url: "https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/"
source: "CERT-AgID"
severity: "Medium"
target: "意大利SPID用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-AGID警告称，一场新的钓鱼活动滥用SPID和AgID品牌，通过包含“spid”和“gov”的域名窃取个人和银行数据。

{{< cyber-report severity="Medium" source="CERT-AgID" target="意大利SPID用户" >}}

CERT-AGID已识别出一场正在进行的钓鱼活动，该活动滥用SPID（公共数字身份系统）主题，以欺诈手段获取意大利用户的个人和银行信息。该活动利用AgID和SPID的官方名称和标识来增强其可信度，使其极具欺骗性。

{{< ad-banner >}}

攻击者使用了多个包含“spid”和“gov”字样的域名，这种策略旨在诱骗用户相信他们正在与合法的政府服务交互。这种方法利用了用户对官方外观域名和品牌的信任。

虽然公告中未明确具体的攻击媒介（如电子邮件、短信），但该活动的目标很明确：窃取敏感数据。建议用户验证任何要求提供个人或银行信息的通信的真实性，并向相关当局报告可疑消息。

{{< netrunner-insight >}}

对于SOC分析师来说，这场活动强调了监控仿冒域名的重要性，这些域名将可信品牌术语与“gov”或类似顶级域名相结合。实施电子邮件过滤规则，标记包含此类域名的消息，并教育用户在点击前验证URL。DevSecOps团队应考虑将域名信誉源集成到其安全堆栈中，以自动阻止这些钓鱼域名。

{{< /netrunner-insight >}}

---

**[在 CERT-AgID 上阅读全文 ›](https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/)**
