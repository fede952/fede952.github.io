---
title: "ثغرة تجاوز عزل isolated-vm تسمح بتنفيذ تعليمات برمجية عن بُعد في مكتبة جافاسكريبت شائعة"
date: "2026-08-21T07:37:09Z"
original_date: "2026-08-20T13:48:24"
lang: "ar"
translationKey: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
slug: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
author: "NewsBot (Validated by Federico Sella)"
description: "ثغرة حرجة في isolated-vm تسمح لجافاسكريبت المعزولة بالهروب إلى المضيف، مما قد يؤدي إلى تنفيذ تعليمات برمجية عن بُعد. جميع الإصدارات حتى 7.0.0 متأثرة."
original_url: "https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html"
source: "The Hacker News"
severity: "Critical"
target: "مكتبة عزل جافاسكريبت isolated-vm"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ثغرة حرجة في isolated-vm تسمح لجافاسكريبت المعزولة بالهروب إلى المضيف، مما قد يؤدي إلى تنفيذ تعليمات برمجية عن بُعد. جميع الإصدارات حتى 7.0.0 متأثرة.

{{< cyber-report severity="Critical" source="The Hacker News" target="مكتبة عزل جافاسكريبت isolated-vm" >}}

تم الكشف عن ثغرة أمنية حرجة في isolated-vm، وهي مكتبة عزل جافاسكريبت مفتوحة المصدر تستخدم على نطاق واسع مع أكثر من 2900 نجمة و190 شوكة على GitHub. الثغرة، التي تم تتبعها باسم GHSA-864f-rcv7-6rh4، تسمح للمهاجمين بتجاوز بيئة العزل وتنفيذ تعليمات برمجية عشوائية على النظام المضيف. جميع إصدارات المكتبة حتى 7.0.0 متأثرة.

{{< ad-banner >}}

تعتبر الثغرة مثيرة للقلق بشكل خاص لأن isolated-vm مصممة لتوفير حدود آمنة لتشغيل كود جافاسكريبت غير الموثوق. يمكن أن يؤدي تجاوز العزل الناجح إلى اختراق التطبيق المضيف والبنية التحتية الأساسية. على الرغم من عدم تعيين معرّف CVE حتى الآن، يسلط التقرير الضوء على الحاجة إلى اهتمام فوري من المطورين الذين يستخدمون هذه المكتبة.

يجب على المؤسسات التي تعتمد على isolated-vm مراقبة التصحيحات والنظر في اتخاذ إجراءات تخفيفية، مثل تقييد تنفيذ التعليمات البرمجية غير الموثوقة أو تطبيق طبقات عزل إضافية. عدم وجود CVE في هذا الوقت لا يقلل من خطورة الثغرة، حيث قد تكون استغلالات إثبات المفهوم متداولة بالفعل في مجتمع الأمن.

{{< netrunner-insight >}}

هذا الهروب من العزل هو تذكير صارخ بأن أدوات العزل المصممة خصيصًا يمكن أن تحتوي على ثغرات حرجة. يجب على محللي SOC جرد أي تطبيقات تستخدم isolated-vm وإعطاء الأولوية للتصحيح بمجرد توفر الإصلاح. يجب على فرق DevSecOps أيضًا مراجعة استراتيجيات العزل الخاصة بهم والنظر في الدفاع المتعمق، مثل تشغيل العزلات في حاويات أو أجهزة افتراضية منفصلة للحد من نطاق الانفجار.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html)**
