---
title: "ثغرة خطيرة في برنامج البريد الإلكتروني Exim تسمح بتنفيذ الأوامر عن بُعد"
date: "2026-05-14T09:33:22Z"
original_date: "2026-05-13T20:23:50"
lang: "ar"
translationKey: "critical-exim-mailer-flaw-allows-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "ثغرة أمنية خطيرة في تكوينات وكيل نقل البريد Exim قد تسمح للمهاجمين غير المصادق عليهم بتنفيذ أكواد عشوائية عن بُعد. قم بتطبيق التصحيح فوراً."
original_url: "https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/"
source: "BleepingComputer"
severity: "Critical"
target: "وكيل نقل البريد Exim"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ثغرة أمنية خطيرة في تكوينات وكيل نقل البريد Exim قد تسمح للمهاجمين غير المصادق عليهم بتنفيذ أكواد عشوائية عن بُعد. قم بتطبيق التصحيح فوراً.

{{< cyber-report severity="Critical" source="BleepingComputer" target="وكيل نقل البريد Exim" >}}

تم اكتشاف ثغرة أمنية خطيرة في وكيل نقل البريد مفتوح المصدر Exim تؤثر على تكوينات معينة. يمكن أن تسمح هذه الثغرة لمهاجم عن بُعد غير مصادق عليه بتنفيذ أكواد عشوائية على الأنظمة الضعيفة.

{{< ad-banner >}}

يُستخدم Exim على نطاق واسع كخادم بريد على الأنظمة الشبيهة بـ Unix، مما يجعل هذه الثغرة مثيرة للقلق بشكل خاص للمؤسسات التي تعتمد عليه في توصيل البريد الإلكتروني. لم يتم الكشف عن التفاصيل الفنية الدقيقة للاستغلال بالكامل، لكن التصنيف الخطير يشير إلى ضرورة التصحيح الفوري.

يجب على المسؤولين مراجعة تكوينات Exim الخاصة بهم وتطبيق أي تحديثات متاحة من مشروع Exim. إلى حين نشر التصحيحات، يُنصح بتنفيذ ضوابط وصول على مستوى الشبكة للحد من التعرض للخدمة الضعيفة.

{{< netrunner-insight >}}

هذا ناقل خطير لتنفيذ الأوامر عن بُعد في وكيل نقل بريد واسع الانتشار. يجب على محللي SOC تحديد أولويات المسح بحثاً عن مثيلات Exim والتحقق من تعزيز التكوين. يجب على فرق DevSecOps الإسراع في التصحيح والنظر في قواعد جدار حماية تطبيقات الويب (WAF) لحظر محاولات الاستغلال حتى يتم تطبيق التحديثات.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على BleepingComputer ›](https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/)**
