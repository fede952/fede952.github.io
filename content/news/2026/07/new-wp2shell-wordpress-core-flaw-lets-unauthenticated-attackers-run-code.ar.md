---
title: "ثغرة جديدة في WordPress Core تسمى wp2shell تسمح للمهاجمين غير الموثَّقين بتنفيذ الأكواد"
date: "2026-07-18T08:47:36Z"
original_date: "2026-07-17T21:20:10"
lang: "ar"
translationKey: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
slug: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
author: "NewsBot (Validated by Federico Sella)"
description: "يمكن لطلب HTTP مجهول تنفيذ أكواد على مواقع WordPress. تؤثر الثغرة على النواة، لذا حتى التثبيتات الأساسية قابلة للاستغلال. كل موقع يعمل بالإصدارين 6.9 و7.0 كان معرضًا للخطر حتى تم التصحيح."
original_url: "https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html"
source: "The Hacker News"
severity: "Critical"
target: "نواة WordPress (الإصداران 6.9 و7.0)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

يمكن لطلب HTTP مجهول تنفيذ أكواد على مواقع WordPress. تؤثر الثغرة على النواة، لذا حتى التثبيتات الأساسية قابلة للاستغلال. كل موقع يعمل بالإصدارين 6.9 و7.0 كان معرضًا للخطر حتى تم التصحيح.

{{< cyber-report severity="Critical" source="The Hacker News" target="نواة WordPress (الإصداران 6.9 و7.0)" >}}

تم اكتشاف ثغرة حرجة لتنفيذ الأكواد عن بُعد دون مصادقة في نواة WordPress، وتؤثر على الإصدارين 6.9 و7.0. تسمح الثغرة، المسماة wp2shell، للمهاجم بتنفيذ أكواد عشوائية على الموقع المستهدف عن طريق إرسال طلب HTTP مصمم خصيصًا. ومن الجدير بالذكر أن الثغرة موجودة في البرنامج الأساسي، مما يعني أنه حتى تثبيت WordPress الجديد بدون إضافات قابل للاستغلال.

{{< ad-banner >}}

تم نشر التفاصيل التقنية الكاملة وإثبات المفهوم العملي، بالإضافة إلى معرفات CVE المخصصة للثغرتين الأساسيتين. كما تم تحديد حالة ذاكرة تخزين مؤقت للكائنات الدائمة قد تعقد الاستغلال في بعض البيئات. جميع المواقع التي تعمل بالإصدارات المتأثرة كانت تعتبر معرضة للخطر حتى تم تطبيق التصحيحات.

يُحث المسؤولون على التحديث فورًا إلى أحدث إصدار مصحح. نظرًا لسهولة الاستغلال والاستخدام الواسع لـ WordPress، تشكل هذه الثغرة تهديدًا كبيرًا لأمن الويب. يجب على المؤسسات إعطاء الأولوية للتصحيح ومراجعة قواعد جدار الحماية لتطبيقات الويب لكشف ومنع محاولات الاستغلال.

{{< netrunner-insight >}}

هذا مثال نموذجي على ضرورة تحصين البرامج الأساسية ضد الهجمات غير الموثَّقة. يجب على محللي SOC المسح فورًا عن مثيلات WordPress 6.9 و7.0 والتحقق من حالة التصحيح. يجب على فرق DevSecOps اعتبار هذا تذكيرًا بتنفيذ الحماية الذاتية للتطبيقات وقت التشغيل (RASP) ومراقبة طلبات HTTP الشاذة التي تستهدف wp-admin أو wp-includes.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html)**
