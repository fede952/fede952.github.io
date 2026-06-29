---
title: "KDDI数据泄露暴露六家ISP的1420万电子邮件登录信息"
date: "2026-06-29T11:56:07Z"
original_date: "2026-06-28T14:13:46"
lang: "zh-cn"
translationKey: "kddi-data-breach-exposes-14-2-million-email-logins-across-six-isps"
author: "NewsBot (Validated by Federico Sella)"
description: "日本电信公司KDDI披露了一起影响其他五家ISP的电子邮件系统泄露事件，最多可能涉及1420万用户凭据。"
original_url: "https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/"
source: "BleepingComputer"
severity: "High"
target: "日本ISP电子邮件系统"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

日本电信公司KDDI披露了一起影响其他五家ISP的电子邮件系统泄露事件，最多可能涉及1420万用户凭据。

{{< cyber-report severity="High" source="BleepingComputer" target="日本ISP电子邮件系统" >}}

日本电信运营商KDDI公司披露了一起数据泄露事件，威胁行为者入侵了其一个电子邮件系统，该系统被国内其他五家互联网服务提供商（ISP）使用。此次泄露可能暴露了多达1420万个电子邮件登录信息，影响了多家提供商的众多用户。

{{< ad-banner >}}

被入侵的系统是KDDI电子邮件基础设施的一部分，该基础设施为多家ISP提供后端支持。虽然入侵的具体方法尚未披露，但该事件凸显了共享服务提供商架构中固有的风险，即单点故障可能波及多个组织。

KDDI已通知受影响的ISP，并正在努力控制泄露范围。建议用户更改密码，并在可用的情况下启用多因素认证。该事件强调了需要对共享基础设施组件进行强健的隔离和监控。

{{< netrunner-insight >}}

此次泄露是ISP生态系统中供应链风险的典型例子。SOC分析师应优先监控从电子邮件系统向其他关键资产的横向移动，而DevSecOps团队必须对共享后端服务实施严格的网络隔离和最小权限访问。预计未来几周内将有针对这些暴露账户的凭证填充攻击。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/)**
