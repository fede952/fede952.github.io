---
title: "CISA تضيف ثغرة RCE حرجة في PTC Windchill إلى KEV وسط هجمات ويب شل نشطة"
date: "2026-06-27T09:25:09Z"
original_date: "2026-06-26T12:31:56"
lang: "ar"
translationKey: "cisa-adds-ptc-windchill-rce-flaw-to-kev-amid-active-web-shell-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA تضيف ثغرة تنفيذ تعليمات برمجية عن بُعد حرجة في PTC Windchill PDMlink و FlexPLM إلى كتالوج الثغرات المستغلة المعروفة بسبب الاستغلال النشط."
original_url: "https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html"
source: "The Hacker News"
severity: "Critical"
target: "PTC Windchill PDMlink و FlexPLM"
cve: null
cvss: null
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA تضيف ثغرة تنفيذ تعليمات برمجية عن بُعد حرجة في PTC Windchill PDMlink و FlexPLM إلى كتالوج الثغرات المستغلة المعروفة بسبب الاستغلال النشط.

{{< cyber-report severity="Critical" source="The Hacker News" target="PTC Windchill PDMlink و FlexPLM" kev="true" >}}

أضافت وكالة الأمن السيبراني وأمن البنية التحتية الأمريكية (CISA) ثغرة تنفيذ تعليمات برمجية عن بُعد حرجة تؤثر على PTC Windchill PDMlink و PTC FlexPLM إلى كتالوج الثغرات المستغلة المعروفة (KEV). يأتي هذا القرار بعد أدلة على استغلال نشط، مع تقارير تشير إلى هجمات ويب شل مستمرة تستهدف أنظمة إدارة بيانات المنتج (PDM) وإدارة دورة حياة المنتج (PLM) المؤسسية هذه.

{{< ad-banner >}}

على الرغم من عدم الكشف عن معرف CVE محدد في الإعلان، إلا أن الثغرة توصف بأنها ثغرة RCE حرجة يمكن أن تسمح للمهاجمين بتنفيذ تعليمات برمجية عشوائية على الأنظمة المتأثرة. تُحث المؤسسات التي تستخدم هذه المنتجات على إعطاء الأولوية للتصحيح ومراجعة بيئاتها بحثًا عن علامات الاختراق، حيث قد يؤدي الاستغلال إلى السيطرة الكاملة على النظام.

يعمل كتالوج KEV الخاص بـ CISA كتوجيه تشغيلي ملزم للوكالات الفيدرالية، ويتطلب المعالجة ضمن جداول زمنية محددة. يُنصح بشدة مؤسسات القطاع الخاص بالتعامل مع هذا التهديد كأولوية عالية وتنفيذ إجراءات تخفيف مثل تجزئة الشبكة ومراقبة نشاط ويب شل غير المعتاد.

{{< netrunner-insight >}}

لمحللي SOC، أعط الأولوية للبحث عن مؤشرات ويب شل على خوادم Windchill المكشوفة - ابحث عن عمليات فرعية غير عادية تم إنشاؤها بواسطة التطبيق أو اتصالات صادرة إلى عناوين IP غير معروفة. يجب على فرق DevSecOps تطبيق التصحيحات المتاحة فورًا والنظر في نشر التصحيح الافتراضي أو قواعد جدار حماية تطبيقات الويب (WAF) إذا تأخر التصحيح. هذا تذكير بأن أنظمة PLM، التي غالبًا ما يتم تجاهلها في إدارة التصحيح، هي أهداف جذابة لمجموعات برامج الفدية.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html)**
