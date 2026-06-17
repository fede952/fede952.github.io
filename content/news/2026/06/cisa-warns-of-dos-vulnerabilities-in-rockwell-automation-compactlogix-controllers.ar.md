---
title: "CISA تحذر من ثغرات رفض الخدمة في وحدات التحكم Rockwell Automation CompactLogix"
date: "2026-06-17T11:46:16Z"
original_date: "2026-06-16T12:00:00"
lang: "ar"
translationKey: "cisa-warns-of-dos-vulnerabilities-in-rockwell-automation-compactlogix-controllers"
author: "NewsBot (Validated by Federico Sella)"
description: "ثغرات متعددة في وحدات التحكم Rockwell Automation CompactLogix 5370 قد تسمح بهجمات رفض الخدمة. CVE-2025-11694 من بين هذه الثغرات."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04"
source: "CISA"
severity: "High"
target: "وحدات التحكم Rockwell Automation CompactLogix 5370"
cve: "CVE-2025-11694"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ثغرات متعددة في وحدات التحكم Rockwell Automation CompactLogix 5370 قد تسمح بهجمات رفض الخدمة. CVE-2025-11694 من بين هذه الثغرات.

{{< cyber-report severity="High" source="CISA" target="وحدات التحكم Rockwell Automation CompactLogix 5370" cve="CVE-2025-11694" cvss="7.5" >}}

أصدرت CISA نشرة استشارية (ICSA-26-167-04) توضح بالتفصيل الثغرات في وحدات التحكم Rockwell Automation CompactLogix 5370 (L1، L2، L3). تشمل الثغرات التحقق غير السليم من قيم التكامل وكشف معلومات حساسة للنظام، مما قد يسمح للمهاجم بالتسبب في حالة رفض الخدمة. تؤثر النشرة على الإصدارات السابقة لـ V38.011.

{{< ad-banner >}}

أبرز الثغرات، CVE-2025-11694، تتعلق بعدم التحقق من أرقام التسلسل وعناوين IP المصدر في بروتوكول CIP. يمكن للمهاجم استغلال معرفات الاتصال المكشوفة على الواجهة الإلكترونية لتنفيذ هجمات رفض الخدمة، مما يؤدي إلى خطأ بسيط. درجة CVSS v3 لهذه الثغرة هي 7.5.

توصي Rockwell Automation بالتحديث إلى الإصدار V38.011 لمعالجة هذه المشكلات. المنتجات المتأثرة منتشرة عالميًا عبر قطاع التصنيع الحيوي. يجب على المؤسسات إعطاء الأولوية لتصحيح هذه الوحدات للتخفيف من الاضطرابات التشغيلية المحتملة.

{{< netrunner-insight >}}

لمحللي SOC، راقب أنماط حركة CIP غير المعتادة أو محاولات الاتصال المتكررة التي تستهدف وحدات التحكم CompactLogix. يجب على مهندسي DevSecOps التأكد من عدم تعريض الواجهة الإلكترونية لشبكات غير موثوقة وتطبيق تحديث البرنامج الثابت إلى V38.011 فورًا. هذا ناقل بسيط لرفض الخدمة يمكن التخفيف منه من خلال تجزئة الشبكة المناسبة وإدارة التصحيحات.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04)**
