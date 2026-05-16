---
title: "ثغرات في Siemens Teamcenter تهدد التوفر والسلامة والسرية"
date: "2026-05-16T08:47:33Z"
original_date: "2026-05-14T12:00:00"
lang: "ar"
translationKey: "siemens-teamcenter-flaws-risk-availability-integrity-confidentiality"
author: "NewsBot (Validated by Federico Sella)"
description: "ثغرات متعددة في Siemens Teamcenter قد تعرض التوفر والسلامة والسرية للخطر. قم بالتحديث إلى أحدث الإصدارات فورًا."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04"
source: "CISA"
severity: "High"
target: "Siemens Teamcenter"
cve: "CVE-2024-4367"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ثغرات متعددة في Siemens Teamcenter قد تعرض التوفر والسلامة والسرية للخطر. قم بالتحديث إلى أحدث الإصدارات فورًا.

{{< cyber-report severity="High" source="CISA" target="Siemens Teamcenter" cve="CVE-2024-4367" cvss="7.5" >}}

يتأثر Siemens Teamcenter بعدة ثغرات قد تؤدي إلى اختراق التوفر والسلامة والسرية. تشمل العيوب فحصًا غير صحيح للظروف غير العادية أو الاستثنائية، والبرمجة النصية عبر المواقع، واستخدام بيانات اعتماد مشفرة بشكل ثابت. تشمل الإصدارات المتأثرة Teamcenter V2312 وV2406 وV2412 وV2506 وV2512.

{{< ad-banner >}}

CVE-2024-4367 هو نقص في التحقق من النوع عند معالجة الخطوط في PDF.js، مما يسمح بتنفيذ JavaScript تعسفي في سياق PDF.js. تؤثر هذه الثغرة على Firefox وThunderbird ولكنها مدرجة في تنبيه Siemens. توصي Siemens بالتحديث إلى أحدث إصدارات Teamcenter للتخفيف من هذه المخاطر.

تبلغ درجة CVSS v3 الأساسية للثغرات 7.5، مما يشير إلى خطورة عالية. تتأثر قطاعات التصنيع الحيوية، مع نشر عالمي. يجب على المؤسسات إعطاء الأولوية للتصحيح ومراجعة تعرضها لهذه الثغرات.

{{< netrunner-insight >}}

يجب على محللي SOC فورًا جرد جميع مثيلات Teamcenter وإعطاء الأولوية للتصحيح إلى أحدث الإصدارات. يجب على فرق DevSecOps التأكد من تحديث مكونات PDF.js ومراقبة محاولات الاستغلال التي تستهدف هذه الثغرات. نظرًا لارتفاع درجة CVSS واحتمال الاختراق الكامل، تعامل مع هذا كإجراء علاجي عالي الأولوية.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04)**
