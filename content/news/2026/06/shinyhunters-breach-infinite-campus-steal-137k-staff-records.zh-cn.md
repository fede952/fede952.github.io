---
title: "ShinyHunters 入侵 Infinite Campus，窃取 13.7 万条教职员工记录"
date: "2026-06-15T13:03:47Z"
original_date: "2026-06-15T12:38:55"
lang: "zh-cn"
translationKey: "shinyhunters-breach-infinite-campus-steal-137k-staff-records"
author: "NewsBot (Validated by Federico Sella)"
description: "ShinyHunters 团伙在 3 月通过针对 Infinite Campus K-12 系统的 Salesforce 攻击，窃取了 13.7 万个学校教职员工账户的个人数据。"
original_url: "https://www.bleepingcomputer.com/news/security/infinite-campus-data-breach-affects-137-000-school-staff-accounts/"
source: "BleepingComputer"
severity: "High"
target: "Infinite Campus K-12 学生信息系统"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ShinyHunters 团伙在 3 月通过针对 Infinite Campus K-12 系统的 Salesforce 攻击，窃取了 13.7 万个学校教职员工账户的个人数据。

{{< cyber-report severity="High" source="BleepingComputer" target="Infinite Campus K-12 学生信息系统" >}}

勒索团伙 ShinyHunters 声称对针对 Infinite Campus 的数据泄露事件负责，Infinite Campus 是一个广泛使用的 K-12 学生信息系统。此次攻击发生在 3 月，涉及 Salesforce 数据盗窃，导致超过 13.7 万个学校教职员工账户受损，个人信息被泄露。

{{< ad-banner >}}

被盗数据包括学校教职员工的姓名、电子邮件地址及其他个人身份信息（PII）。Infinite Campus 尚未披露此次泄露的全部范围，也未说明学生数据是否受到影响，但该事件凸显了教育技术平台在针对性勒索活动中的脆弱性。

ShinyHunters 以在地下论坛出售被盗数据而闻名，此前曾针对多家大公司。此次泄露事件强调了基于云的教育系统（尤其是处理敏感教职员工和学生信息的系统）需要采取强有力的安全措施。

{{< netrunner-insight >}}

此次泄露表明，威胁行为者正越来越多地通过受损的 Salesforce 实例针对基于云的教育平台。SOC 分析师应优先监控异常的 Salesforce API 活动，并对所有教职员工账户强制执行多因素认证。DevSecOps 团队必须确保第三方集成得到适当范围界定和审计，以防止从受损的 SaaS 应用进行横向移动。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/infinite-campus-data-breach-affects-137-000-school-staff-accounts/)**
