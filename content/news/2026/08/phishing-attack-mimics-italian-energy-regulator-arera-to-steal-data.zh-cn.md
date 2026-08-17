---
title: "钓鱼攻击冒充意大利能源监管机构ARERA窃取数据"
date: "2026-08-17T07:49:27Z"
original_date: "2026-08-05T13:20:37"
lang: "zh-cn"
translationKey: "phishing-attack-mimics-italian-energy-regulator-arera-to-steal-data"
slug: "phishing-attack-mimics-italian-energy-regulator-arera-to-steal-data"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-AGID警告称，存在一个冒充ARERA的欺诈网站，利用水费社会补助作为诱饵，通过域名仿冒手段窃取个人和财务数据。"
original_url: "https://cert-agid.gov.it/news/phishing-ai-danni-di-arera-utilizza-il-tema-bonus-sociale-idrico/"
source: "CERT-AgID"
severity: "Medium"
target: "意大利公民及ARERA用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-AGID警告称，存在一个冒充ARERA的欺诈网站，利用水费社会补助作为诱饵，通过域名仿冒手段窃取个人和财务数据。

{{< cyber-report severity="Medium" source="CERT-AgID" target="意大利公民及ARERA用户" >}}

CERT-AGID发现了一个冒充ARERA（意大利能源、网络和环境监管局）名称和标志的欺诈网站。该网站以提供与水费社会补助相关的退款为诱饵，吸引受害者。水费社会补助是一项旨在为经济困难或身体困难的家庭降低供水成本的合法措施。

{{< ad-banner >}}

该钓鱼活动采用域名仿冒技术，使虚假域名看起来几乎与合法的ARERA网站相同，以增加其可信度。其目的是诱骗用户泄露个人和财务信息，这些信息随后可能被用于身份盗窃或金融欺诈。

此事件凸显了利用知名政府或监管机构进行钓鱼活动的持续威胁。建议用户核实任何声称提供退款或补助的通信的真实性，并避免点击未经请求的电子邮件或消息中的链接。

{{< netrunner-insight >}}

对于SOC分析师而言，此活动强调了监控与关键公共服务相关的仿冒域名的必要性。实施DNS过滤并教育用户验证官方渠道可以缓解此类威胁。DevSecOps团队应考虑集成跟踪相似域名的威胁情报源，以主动阻止访问。

{{< /netrunner-insight >}}

---

**[在 CERT-AgID 上阅读全文 ›](https://cert-agid.gov.it/news/phishing-ai-danni-di-arera-utilizza-il-tema-bonus-sociale-idrico/)**
