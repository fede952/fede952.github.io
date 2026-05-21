---
title: "تجاوز MFA لـ SonicWall VPN بسبب التصحيح غير الكامل"
date: "2026-05-21T10:35:14Z"
original_date: "2026-05-20T21:19:17"
lang: "ar"
translationKey: "sonicwall-vpn-mfa-bypassed-due-to-incomplete-patching"
author: "NewsBot (Validated by Federico Sella)"
description: "يخترق المهاجمون بيانات اعتماد VPN بالقوة ويتجاوزون MFA على أجهزة SonicWall Gen6 SSL-VPN غير المصححة، وينشرون أدوات برامج الفدية."
original_url: "https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/"
source: "BleepingComputer"
severity: "High"
target: "أجهزة SonicWall Gen6 SSL-VPN"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

يخترق المهاجمون بيانات اعتماد VPN بالقوة ويتجاوزون MFA على أجهزة SonicWall Gen6 SSL-VPN غير المصححة، وينشرون أدوات برامج الفدية.

{{< cyber-report severity="High" source="BleepingComputer" target="أجهزة SonicWall Gen6 SSL-VPN" >}}

لوحظ أن المهاجمين يخترقون بيانات اعتماد VPN بالقوة ويتجاوزون المصادقة متعددة العوامل (MFA) على أجهزة SonicWall Gen6 SSL-VPN. تستغل الهجمات التصحيح غير الكامل، مما يسمح للخصوم بنشر أدوات شائعة الاستخدام في عمليات برامج الفدية.

{{< ad-banner >}}

تمكن الثغرة المهاجمين من الوصول غير المصرح به إلى الشبكات الداخلية بعد اختراق بيانات اعتماد VPN. وبمجرد الدخول، يمكنهم التحرك جانبيًا ونشر حمولات برامج الفدية، مما يشكل خطرًا كبيرًا على المؤسسات التي تعتمد على هذه الأجهزة للوصول عن بُعد.

أصدرت SonicWall تصحيحات لمعالجة المشكلة، لكن التطبيق غير الكامل لهذه التحديثات يترك الأنظمة مكشوفة. تُحث المؤسسات على التحقق من تثبيت جميع التصحيحات الموصى بها بالكامل ومراقبة علامات الوصول غير المصرح به إلى VPN.

{{< netrunner-insight >}}

تؤكد هذه الحادثة على الأهمية الحاسمة لإدارة التصحيح الشاملة. يجب على محللي SOC إعطاء الأولوية للتحقق من أن جميع أجهزة SonicWall Gen6 لديها أحدث البرامج الثابتة ومراقبة سجلات VPN لأنماط المصادقة الشاذة. يجب على فرق DevSecOps النظر في تنفيذ طبقات MFA إضافية وتقسيم الشبكة للتخفيف من مثل هذه التجاوزات.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/)**
