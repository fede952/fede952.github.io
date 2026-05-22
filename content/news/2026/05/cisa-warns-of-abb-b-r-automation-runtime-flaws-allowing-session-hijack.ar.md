---
title: "CISA تحذر من ثغرات في ABB B&R Automation Runtime تسمح باختطاف الجلسات"
date: "2026-05-22T10:20:32Z"
original_date: "2026-05-21T12:00:00"
lang: "ar"
translationKey: "cisa-warns-of-abb-b-r-automation-runtime-flaws-allowing-session-hijack"
author: "NewsBot (Validated by Federico Sella)"
description: "ثغرات متعددة في ABB B&R Automation Runtime قبل الإصدار 6.4 قد تسمح للمهاجمين باختطاف الجلسات أو تنفيذ الأكواد. توضح نشرة CISA ICSA-26-141-04 الإصلاحات."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04"
source: "CISA"
severity: "Medium"
target: "ABB B&R Automation Runtime"
cve: "CVE-2025-3449"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ثغرات متعددة في ABB B&R Automation Runtime قبل الإصدار 6.4 قد تسمح للمهاجمين باختطاف الجلسات أو تنفيذ الأكواد. توضح نشرة CISA ICSA-26-141-04 الإصلاحات.

{{< cyber-report severity="Medium" source="CISA" target="ABB B&R Automation Runtime" cve="CVE-2025-3449" cvss="6.1" >}}

أصدرت CISA النشرة ICSA-26-141-04 التي تفصل ثغرات متعددة في ABB B&R Automation Runtime، وهي منصة برمجية تستخدم في الأتمتة الصناعية. تم تحديد الثغرات من خلال التحليل الأمني الداخلي لـ B&R، وتؤثر على الإصدارات السابقة للإصدار 6.4 وتشمل CVE-2025-3449 (معرفات جلسة قابلة للتوقع)، وCVE-2025-3448 (البرمجة النصية عبر المواقع)، وCVE-2025-11498 (تحييد غير صحيح لعناصر الصيغ في ملفات CSV). يمكن لمهاجم غير مصادق استغلال هذه الثغرات لاختطاف الجلسات عن بُعد أو تنفيذ الأكواد في سياق متصفح المستخدم.

{{< ad-banner >}}

أكثر الثغرات خطورة، CVE-2025-3449، توجد في مكون System Diagnostic Manager (SDM) وتحصل على درجة 6.1 في CVSS v3. تسمح لمهاجم غير مصادق عبر الشبكة بالاستيلاء على الجلسات القائمة بالفعل بسبب توليد أرقام أو معرفات قابلة للتوقع. يتم تعطيل SDM افتراضيًا في Automation Runtime 6، مما يقلل من التعرض، ولكن يجب على المؤسسات التحقق من بقائه معطلاً ما لم يكن مطلوبًا بشكل صريح.

أصدرت ABB الإصدار 6.4 من Automation Runtime لمعالجة هذه المشكلات. نظرًا لنشر المنتج عبر قطاع الطاقة عالميًا، تحث CISA المشغلين على تطبيق التحديث فورًا. تشير النشرة إلى أن الاستغلال الناجح قد يؤدي إلى تنفيذ الأكواد عن بُعد أو الاستيلاء على الجلسات، مما يشكل خطرًا كبيرًا على بيئات التحكم الصناعي.

{{< netrunner-insight >}}

لمحللي SOC: إعطاء الأولوية لتصحيح مثيلات Automation Runtime، خاصة تلك التي تم تمكين SDM فيها. ثغرة معرف الجلسة القابل للتوقع (CVE-2025-3449) قابلة للاستغلال بسهولة عبر الشبكة. يجب على فرق DevSecOps التأكد من بقاء SDM معطلاً في الإنتاج والتحقق من عدم إمكانية الوصول إلى أي مثيلات مكشوفة من شبكات غير موثوقة. راقب نشاط الجلسات غير المعتاد كإشارة كشف.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04)**
