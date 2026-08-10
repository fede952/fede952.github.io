---
title: "هجوم TONTOU على وحدة المعالجة المركزية يتجاوز إصلاحات Spectre v2 ويكشف تجزئات كلمات المرور في Linux"
date: "2026-08-10T08:26:15Z"
original_date: "2026-08-06T18:03:45"
lang: "ar"
translationKey: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
slug: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "يطور الباحثون هجوم TONTOU الذي يتجاوز التخفيفات الأخيرة لثغرة Spectre v2، مما يؤدي إلى تسريب أسرار بما في ذلك تجزئات كلمات المرور من أنظمة Linux."
original_url: "https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/"
source: "BleepingComputer"
severity: "High"
target: "أنظمة Linux"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

يطور الباحثون هجوم TONTOU الذي يتجاوز التخفيفات الأخيرة لثغرة Spectre v2، مما يؤدي إلى تسريب أسرار بما في ذلك تجزئات كلمات المرور من أنظمة Linux.

{{< cyber-report severity="High" source="BleepingComputer" target="أنظمة Linux" >}}

كشف باحثو الأمن عن هجوم جديد لتنفيذ التخمين، أطلق عليه اسم TONTOU، يتجاوز التخفيفات الأخيرة لثغرة Spectre v2. يستهدف الهجوم آليات التنبؤ بالفروع في وحدة المعالجة المركزية، والتي تم تصحيحها سابقًا لمنع تسرب القنوات الجانبية. من خلال استغلال ثغرة في هذه الدفاعات، تمكن الباحثون من استخراج بيانات حساسة من ذاكرة النواة لأجهزة Linux.

{{< ad-banner >}}

يُظهر إثبات المفهوم للاستغلال خطورة المشكلة من خلال تسريب تجزئات كلمات المرور من النظام المستهدف بنجاح. يشير هذا إلى أن الهجوم يمكن استخدامه لاختراق بيانات اعتماد المستخدم وربما تصعيد الامتيازات. تسلط النتائج الضوء على التحدي المستمر في التخفيف الكامل من هجمات القنوات الجانبية لتنفيذ التخمين، حيث تستمر أشكال جديدة في الظهور على الرغم من الإصلاحات السابقة.

على الرغم من أن الباحثين لم ينشروا بعد التفاصيل الفنية الكاملة، إلا أن عملهم يؤكد الحاجة إلى اليقظة المستمرة في أمن وحدة المعالجة المركزية. يُنصح مسؤولو الأنظمة بمراقبة التحديثات من موردي وحدات المعالجة المركزية وتوزيعات Linux، والنظر في تدابير تحصين إضافية مثل توزيع عشوائي لمساحة عنوان النواة (KASLR) وتحديثات البرامج الدقيقة.

{{< netrunner-insight >}}

هذا الهجوم تذكير صارخ بأن ثغرات تنفيذ التخمين لم تُحل بالكامل. يجب على محللي SOC إعطاء الأولوية للتصحيح ومراقبة أي مؤشرات على الاستغلال، بينما يجب على مهندسي DevSecOps مراجعة نماذج التهديد الخاصة بهم بحثًا عن مخاطر القنوات الجانبية. نظرًا لإمكانية تسريب تجزئات كلمات المرور، فإن الاهتمام الفوري بتحديثات نواة Linux والبرامج الدقيقة لوحدة المعالجة المركزية أمر مبرر.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على BleepingComputer ›](https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/)**
