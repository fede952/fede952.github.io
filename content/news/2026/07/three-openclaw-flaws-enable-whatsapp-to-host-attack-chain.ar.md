---
title: "ثلاث ثغرات في OpenClaw تمكن سلسلة هجوم من واتساب إلى المضيف"
date: "2026-07-11T08:46:01Z"
original_date: "2026-07-10T14:19:50"
lang: "ar"
translationKey: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
slug: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
author: "NewsBot (Validated by Federico Sella)"
description: "يكشف باحث عن ثلاث ثغرات عالية الخطورة في OpenClaw قد تسمح بسرقة بيانات الاعتماد، وتصعيد الامتيازات، وتنفيذ الأكواد على المضيف."
original_url: "https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html"
source: "The Hacker News"
severity: "High"
target: "مساعد OpenClaw الذكي"
cve: null
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

يكشف باحث عن ثلاث ثغرات عالية الخطورة في OpenClaw قد تسمح بسرقة بيانات الاعتماد، وتصعيد الامتيازات، وتنفيذ الأكواد على المضيف.

{{< cyber-report severity="High" source="The Hacker News" target="مساعد OpenClaw الذكي" cvss="8.8" >}}

ظهرت تفاصيل حول ثلاث ثغرات أمنية تم إصلاحها الآن في مساعد OpenClaw الشخصي الذكي، والتي إذا تم استغلالها بنجاح قد تمكن من سرقة بيانات الاعتماد، وتصعيد الامتيازات، وتنفيذ أكواد عشوائية على المضيف. تم الكشف عن الثغرات من قبل باحث أوضح سلسلة هجوم تبدأ من رسائل واتساب.

{{< ad-banner >}}

إحدى الثغرات، المسجلة برقم GHSA-hjr6-g723-hmfm ودرجة CVSS 8.8، توصف بأنها عالية الخطورة. لم يتم تفصيل طبيعة الثغرتين الأخريين بشكل كامل، لكنها تشكل مجتمعة خطرًا كبيرًا على المستخدمين الذين يدمجون OpenClaw مع منصات المراسلة مثل واتساب.

تستغل سلسلة الهجوم قدرة المساعد الذكي على معالجة الرسائل، مما قد يسمح للمهاجم بتصعيد الامتيازات وتنفيذ أكواد عشوائية على النظام المضيف. يُنصح المستخدمون بتطبيق أحدث التصحيحات للتخفيف من هذه المخاطر.

{{< netrunner-insight >}}

تسلط سلسلة الهجوم هذه الضوء على مخاطر دمج المساعدات الذكية مع منصات المراسلة. يجب على محللي SOC مراقبة عمليات تنفيذ غير عادية تنشأ من مكونات المساعد الذكي، بينما يجب على فرق DevSecOps ضمان عزل هذه التكاملات وتصحيحها بشكل فوري.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html)**
