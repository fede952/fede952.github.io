---
title: "7-Zip 26.02 يصحح ثغرة تنفيذ التعليمات البرمجية عن بُعد في الأرشيفات الضارة"
date: "2026-07-19T09:02:18Z"
original_date: "2026-07-18T19:32:02"
lang: "ar"
translationKey: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
slug: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
author: "NewsBot (Validated by Federico Sella)"
description: "أصدر 7-Zip الإصدار 26.02 لإصلاح ثغرة أمنية في تنفيذ التعليمات البرمجية عن بُعد يمكن تفعيلها عن طريق فتح ملفات مضغوطة مصممة خصيصًا. يُوصى بالتحديث فورًا."
original_url: "https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/"
source: "BleepingComputer"
severity: "High"
target: "مستخدمو 7-Zip"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

أصدر 7-Zip الإصدار 26.02 لإصلاح ثغرة أمنية في تنفيذ التعليمات البرمجية عن بُعد يمكن تفعيلها عن طريق فتح ملفات مضغوطة مصممة خصيصًا. يُوصى بالتحديث فورًا.

{{< cyber-report severity="High" source="BleepingComputer" target="مستخدمو 7-Zip" >}}

تم إصدار 7-Zip الإصدار 26.02 لمعالجة ثغرة تنفيذ التعليمات البرمجية عن بُعد (RCE) التي قد تسمح للمهاجمين بتنفيذ تعليمات برمجية عشوائية على نظام الضحية. يمكن استغلال الثغرة عن طريق إقناع المستخدمين بفتح ملفات مضغوطة مصممة خصيصًا، مثل الأرشيفات التي تحتوي على حمولات ضارة.

{{< ad-banner >}}

تؤثر الثغرة على جميع الإصدارات السابقة من أداة ضغط الملفات الشهيرة. على الرغم من عدم الكشف عن معرف CVE في الإعلان، إلا أن خطورتها تعتبر عالية نظرًا لاحتمال اختراق النظام بالكامل. يُنصح المستخدمون بشدة بالتحديث إلى أحدث إصدار فورًا.

نظرًا للاستخدام الواسع لـ 7-Zip في بيئات المؤسسات والمستهلكين على حد سواء، فإن هذا التصحيح ضروري لتقليل سطح الهجوم. يجب على المؤسسات إعطاء الأولوية لنشر التحديث عبر آليات التحديث التلقائي أو التثبيت اليدوي.

{{< netrunner-insight >}}

يجب على محللي SOC مراقبة أي نشاط غير عادي لملفات الأرشيف والتأكد من تحديث 7-Zip على جميع نقاط النهاية. يجب على فرق DevSecOps دمج هذا التحديث في خطط إدارة التصحيحات الخاصة بهم والنظر في حظر الإصدارات الأقدم من 7-Zip من الوصول إلى الأنظمة الحساسة.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على BleepingComputer ›](https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/)**
