---
title: "هجوم تصيد عبر ملفات ZIP تحمل صورًا يستهدف الفنادق باستخدام برنامج Node.js خبيث"
date: "2026-06-26T10:21:21Z"
original_date: "2026-06-26T09:27:12"
lang: "ar"
translationKey: "photo-zip-phishing-hits-hotels-with-node-js-implant"
author: "NewsBot (Validated by Federico Sella)"
description: "تحذر Microsoft من حملة تصيد نشطة تستهدف الفنادق في أوروبا وآسيا عبر ملفات ZIP ذات طابع صوري تؤدي إلى تثبيت برنامج Node.js خبيث."
original_url: "https://thehackernews.com/2026/06/microsoft-warns-of-photo-zip-phishing.html"
source: "The Hacker News"
severity: "High"
target: "مؤسسات الفنادق والضيافة"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تحذر Microsoft من حملة تصيد نشطة تستهدف الفنادق في أوروبا وآسيا عبر ملفات ZIP ذات طابع صوري تؤدي إلى تثبيت برنامج Node.js خبيث.

{{< cyber-report severity="High" source="The Hacker News" target="مؤسسات الفنادق والضيافة" >}}

منذ أبريل 2026، تشن حملة تصيد نشطة تستهدف مؤسسات الفنادق والضيافة في أوروبا وآسيا. يستخدم المهاجمون ملفات ZIP ذات طابع صوري كطعم، والتي عند تنفيذها تقوم بتثبيت برنامج Node.js خبيث على أجهزة الاستقبال.

{{< ad-banner >}}

لم تنسب Microsoft هذا النشاط إلى أي جهة تهديد معروفة، ولا يزال الهدف النهائي للمشغلين غير واضح. تم تصميم الطعم خصيصًا لاستغلال طريقة عمل الفنادق، مما يشير إلى نهج هندسة اجتماعية مخصص.

يمنح برنامج Node.js الخبيث المهاجمين موطئ قدم في الشبكات المستهدفة، مما قد يسمح بالحركة الجانبية وسرقة البيانات. يُنصح المؤسسات في قطاع الضيافة بتوخي الحذر مع مرفقات البريد الإلكتروني غير المرغوب فيها ومراقبة عمليات Node.js المشبوهة.

{{< netrunner-insight >}}

يجب على محللي SOC مراقبة عمليات Node.js غير المعتادة والاتصالات الصادرة من أنظمة الاستقبال. يجب على فرق DevSecOps النظر في حظر تنفيذ نصوص Node.js من مرفقات البريد الإلكتروني وتطبيق القائمة البيضاء للتطبيقات للتخفيف من مثل هذه البرامج الخبيثة.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/06/microsoft-warns-of-photo-zip-phishing.html)**
