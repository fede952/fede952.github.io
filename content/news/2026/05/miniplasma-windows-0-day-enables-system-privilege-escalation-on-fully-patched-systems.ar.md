---
title: "ثغرة يوم الصفر MiniPlasma في ويندوز تسمح برفع الامتيازات إلى SYSTEM على الأنظمة المحدثة بالكامل"
date: "2026-05-18T11:01:35Z"
original_date: "2026-05-18T08:57:34"
lang: "ar"
translationKey: "miniplasma-windows-0-day-enables-system-privilege-escalation-on-fully-patched-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "باحث الأمن Chaotic Eclipse ينشر إثبات المفهوم لـ MiniPlasma، وهي ثغرة يوم الصفر في برنامج تشغيل مرشح الملفات السحابية المصغر في ويندوز (cldflt.sys) تمنح صلاحيات SYSTEM على الأنظمة المحدثة بالكامل."
original_url: "https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html"
source: "The Hacker News"
severity: "High"
target: "برنامج تشغيل مرشح الملفات السحابية المصغر في ويندوز (cldflt.sys)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

باحث الأمن Chaotic Eclipse ينشر إثبات المفهوم لـ MiniPlasma، وهي ثغرة يوم الصفر في برنامج تشغيل مرشح الملفات السحابية المصغر في ويندوز (cldflt.sys) تمنح صلاحيات SYSTEM على الأنظمة المحدثة بالكامل.

{{< cyber-report severity="High" source="The Hacker News" target="برنامج تشغيل مرشح الملفات السحابية المصغر في ويندوز (cldflt.sys)" >}}

Chaotic Eclipse، الباحث الأمني الذي يقف وراء الثغرات التي تم الكشف عنها مؤخرًا في ويندوز YellowKey و GreenPlasma، نشر إثبات المفهوم لثغرة يوم الصفر لرفع الامتيازات في ويندوز تمنح المهاجمين صلاحيات SYSTEM على الأنظمة المحدثة بالكامل. تحمل الثغرة الاسم الرمزي MiniPlasma وتؤثر على "cldflt.sys"، وهو برنامج تشغيل مرشح الملفات السحابية المصغر في ويندوز.

{{< ad-banner >}}

تسمح الثغرة لمهاجم لديه وصول محدود للمستخدم برفع الامتيازات إلى SYSTEM، مما قد يمكن من اختراق النظام بالكامل. وباعتبارها ثغرة يوم الصفر، لا يتوفر تصحيح رسمي حاليًا، مما يترك الأنظمة المحدثة بالكامل عرضة للاستغلال إذا تم تسليح إثبات المفهوم.

يجب على المؤسسات مراقبة السلوك غير المعتاد من برنامج تشغيل cldflt.sys والنظر في إجراءات تعزيز إضافية، مثل تقييد الوصول إلى ميزة الملفات السحابية أو تطبيق إجراءات تخفيف مؤقتة حتى يتم إصدار تصحيح.

{{< netrunner-insight >}}

يجب على محللي SOC إعطاء الأولوية لمراقبة محاولات الاستغلال التي تستهدف cldflt.sys، حيث يخفض إثبات المفهوم الحاجز أمام المهاجمين. يجب على فرق DevSecOps مراجعة تعزيز صور ويندوز الخاصة بهم والنظر في تعطيل برنامج تشغيل مرشح الملفات السحابية المصغر إذا لم يكن مطلوبًا، أثناء انتظار إصلاح رسمي من Microsoft.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)**
