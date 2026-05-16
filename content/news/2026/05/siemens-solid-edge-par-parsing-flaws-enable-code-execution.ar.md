---
title: "ثغرات في تحليل ملفات PAR في Siemens Solid Edge تتيح تنفيذ الأكواد"
date: "2026-05-16T08:48:36Z"
original_date: "2026-05-14T12:00:00"
lang: "ar"
translationKey: "siemens-solid-edge-par-parsing-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "ثغرتان في تحليل الملفات في Siemens Solid Edge SE2026 تسمحان للمهاجمين بتنفيذ أكواد عشوائية عبر ملفات PAR مصممة خصيصًا. قم بالتحديث إلى الإصدار V226.0 Update 5."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03"
source: "CISA"
severity: "High"
target: "Siemens Solid Edge SE2026"
cve: "CVE-2026-44411"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ثغرتان في تحليل الملفات في Siemens Solid Edge SE2026 تسمحان للمهاجمين بتنفيذ أكواد عشوائية عبر ملفات PAR مصممة خصيصًا. قم بالتحديث إلى الإصدار V226.0 Update 5.

{{< cyber-report severity="High" source="CISA" target="Siemens Solid Edge SE2026" cve="CVE-2026-44411" cvss="7.8" >}}

يتأثر Siemens Solid Edge SE2026 قبل الإصدار Update 5 بثغرتين في تحليل الملفات يمكن تشغيلهما عند قراءة التطبيق لملفات PAR مصممة خصيصًا. تشمل الثغرات وصولاً إلى مؤشر غير مهيأ (CVE-2026-44411) وفيضانًا في المخزن المؤقت على المكدس (CVE-2026-44412)، وكلاهما يمكن أن يسمح للمهاجم بتعطيل التطبيق أو تنفيذ أكواد عشوائية في سياق العملية الحالية.

{{< ad-banner >}}

تحمل الثغرات درجة أساسية 7.8 (عالية) وفقًا لـ CVSS v3.1 مع المتجه AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H، مما يشير إلى وصول محلي، تعقيد منخفض، لا حاجة لامتيازات، تفاعل مستخدم مطلوب، وتأثير عالٍ على السرية والنزاهة والتوفر. أصدرت Siemens الإصدار V226.0 Update 5 لمعالجة هذه المشكلات وتوصي المستخدمين بالتحديث فورًا.

نظرًا لنشر القطاع الصناعي الحيوي عالميًا، يجب على المؤسسات التي تستخدم Solid Edge إعطاء الأولوية للتصحيح. تتطلب الثغرات تفاعل المستخدم (فتح ملف PAR ضار)، لذا يُوصى أيضًا بالتدريب على الوعي الأمني كإجراء تعويضي.

{{< netrunner-insight >}}

لمحللي SOC، راقبوا معالجة ملفات PAR غير المعتادة أو الأعطال في عمليات Solid Edge. يجب على مهندسي DevSecOps فرض القائمة البيضاء للتطبيقات وتقييد أنواع الملفات لتقليل سطح الهجوم. نظرًا لأن هذه ثغرات محلية تعتمد على تفاعل المستخدم، فإن محاكاة التصيد وقواعد الكشف عن نقاط النهاية لفتح الملفات المشبوهة هي إجراءات تخفيف رئيسية.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03)**
