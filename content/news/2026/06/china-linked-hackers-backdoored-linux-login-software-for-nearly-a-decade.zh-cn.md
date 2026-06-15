---
title: "与中国有关联的黑客近十年来一直在Linux登录软件中植入后门"
date: "2026-06-15T13:04:59Z"
original_date: "2026-06-12T18:17:55"
lang: "zh-cn"
translationKey: "china-linked-hackers-backdoored-linux-login-software-for-nearly-a-decade"
author: "NewsBot (Validated by Federico Sella)"
description: "一个名为Velvet Ant的中国关联组织入侵了PAM和OpenSSH组件，在Linux登录系统中隐藏了近十年未被发现。"
original_url: "https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html"
source: "The Hacker News"
severity: "High"
target: "Linux登录系统（PAM、OpenSSH）"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

一个名为Velvet Ant的中国关联组织入侵了PAM和OpenSSH组件，在Linux登录系统中隐藏了近十年未被发现。

{{< cyber-report severity="High" source="The Hacker News" target="Linux登录系统（PAM、OpenSSH）" >}}

一个被追踪为Velvet Ant的中国关联威胁行为者被发现已在核心Linux登录组件（包括PAM（可插拔认证模块）和OpenSSH）中植入后门，使其能够维持近十年的持久访问。该组织针对一个网络，将后门深深嵌入认证堆栈中，使其能够抵抗标准的清理程序。

{{< ad-banner >}}

据安全公司Sygnia称，攻击者利用了对登录软件的信任来逃避检测。通过修改控制用户访问的机制，他们确保其立足点能够在系统更新和常规安全扫描中幸存。该活动凸显了国家支持的组织在针对基础基础设施方面日益复杂的手法。

此次入侵事件强调，组织需要监控关键系统组件的完整性，而不仅仅是依赖传统的端点检测。防御者应考虑对PAM模块和SSH二进制文件实施文件完整性监控，并对认证日志进行行为分析，以发现表明登录进程被植入后门的异常情况。

{{< netrunner-insight >}}

对于SOC分析师和DevSecOps团队而言，这是一个鲜明的提醒：攻击者正在针对认证层本身。对PAM和OpenSSH二进制文件实施运行时完整性检查，并考虑使用内核级监控来检测篡改。同时，在事件响应预案中审查基于SSH密钥的认证和PAM配置更改。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html)**
