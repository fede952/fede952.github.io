---
title: "تحديث متصفح مزيف على واي فاي الفندق يوزع حصان طروادة CornFlake"
date: "2026-08-01T09:04:02Z"
original_date: "2026-08-01T06:29:05"
lang: "ar"
translationKey: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
slug: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "تحذر Microsoft من عملية CaptiveCrunch التي تستخدم شبكات واي فاي الفندق المخترقة لدفع تحديثات مزيفة وتوزيع برمجيات خبيثة للتجسس CornFlake."
original_url: "https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html"
source: "The Hacker News"
severity: "High"
target: "مستخدمو واي فاي الفندق"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تحذر Microsoft من عملية CaptiveCrunch التي تستخدم شبكات واي فاي الفندق المخترقة لدفع تحديثات مزيفة وتوزيع برمجيات خبيثة للتجسس CornFlake.

{{< cyber-report severity="High" source="The Hacker News" target="مستخدمو واي فاي الفندق" >}}

كشفت Microsoft عن حملة جديدة تُعرف باسم CaptiveCrunch، والتي تستغل شبكات واي فاي الفندق المخترقة لتقديم تحديثات متصفح مزيفة. هذه التحديثات هي في الواقع حصان طروادة للوصول عن بُعد (RAT) يُسمى CornFlake، قادر على التقاط صور كاميرا الويب، وصوت الميكروفون، وضغطات المفاتيح، مما يحول الأجهزة المصابة إلى أدوات مراقبة.

{{< ad-banner >}}

تُنسب العملية إلى Storm-2945، والتي تقيّمها Microsoft كمجموعة فرعية تشغيلية لمجموعة التهديد المعروفة Midnight Blizzard. يشير هذا إلى مستوى عالٍ من التطور والموارد، حيث تتضمن سلسلة الهجوم اختراق البنية التحتية للشبكات في الفنادق لاعتراض حركة مرور المستخدمين وإعادة توجيهها إلى صفحات تحديث ضارة.

على الرغم من أن التقرير لا يحدد CVE أو درجة CVSS معينة، فإن ناقل الهجوم ملحوظ لاستخدامه بيئة موثوقة (واي فاي الفندق) لتوصيل البرمجيات الخبيثة. المسافرون والمهنيون في الأعمال معرضون للخطر بشكل خاص، حيث يعتمدون غالبًا على شبكات الواي فاي العامة وقد يكونون أكثر عرضة لقبول مطالبات تحديث المتصفح دون تدقيق.

{{< netrunner-insight >}}

تؤكد هذه الحملة على أهمية التعامل مع أي مطالبة بتحديث المتصفح عبر شبكات غير موثوقة بشك. يجب على محللي SOC مراقبة الاتصالات الصادرة غير المعتادة من نقاط النهاية التي اتصلت مؤخرًا بشبكات واي فاي الفندق أو العامة، والنظر في حظر أو الإبلاغ عن المجالات المتعلقة بالتحديثات غير الموجودة في القائمة البيضاء للمؤسسة. بالنسبة لـ DevSecOps، يمكن أن يخفف فرض سياسات تحديث صارمة واستخدام شبكات VPN للمؤسسات للعاملين عن بُعد من خطر هجمات نمط حفرة الري هذه.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html)**
