---
title: "AitM 钓鱼活动针对 Microsoft 365 窃取财务邮件"
date: "2026-08-08T07:47:42Z"
original_date: "2026-08-07T10:38:27"
lang: "zh-cn"
translationKey: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
slug: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
author: "NewsBot (Validated by Federico Sella)"
description: "广泛的邮件驱动型钓鱼利用中间人攻击劫持 Microsoft 365 账户，旨在收集薪资和财务邮件。"
original_url: "https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html"
source: "The Hacker News"
severity: "High"
target: "Microsoft 365 账户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

广泛的邮件驱动型钓鱼利用中间人攻击劫持 Microsoft 365 账户，旨在收集薪资和财务邮件。

{{< cyber-report severity="High" source="The Hacker News" target="Microsoft 365 账户" >}}

网络安全研究人员发现了一个活跃且广泛的邮件驱动型钓鱼活动，该活动利用中间人（AitM）技术入侵 Microsoft 365 账户。该活动的主要目标是识别参与财务流程的关键人员，并窃取相关的电子邮件通信，尤其是涉及薪资和财务的邮件。

{{< ad-banner >}}

攻击者使用住宅代理将其恶意登录伪装成普通消费者流量，从而规避通常标记可疑 IP 地址的安全控制。这种技术使攻击者能够保持持久性并访问被入侵的账户，而不会立即触发警报。

使用 Microsoft 365 的组织应警惕此类 AitM 钓鱼尝试，这些尝试通常通过实时中继凭据和会话令牌来绕过多因素认证。该活动对财务数据的关注表明其旨在促进财务欺诈或商业电子邮件入侵（BEC）。

{{< netrunner-insight >}}

此活动凸显了对抗钓鱼的多因素认证（如 FIDO2 安全密钥）以及持续监控异常登录（尤其是来自住宅 IP 范围的登录）的必要性。SOC 团队还应优先考虑针对 AitM 工具包的检测规则，并实施基于风险信号的条件访问策略。DevSecOps 工程师应考虑实施会话绑定和设备合规性检查，以缓解令牌中继攻击。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html)**
