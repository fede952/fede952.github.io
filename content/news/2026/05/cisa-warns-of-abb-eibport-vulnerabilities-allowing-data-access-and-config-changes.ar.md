---
title: "CISA تحذر من ثغرات أمنية في أجهزة ABB EIBPORT تسمح بالوصول إلى البيانات وتغيير الإعدادات"
date: "2026-05-29T10:43:33Z"
original_date: "2026-05-28T12:00:00"
lang: "ar"
translationKey: "cisa-warns-of-abb-eibport-vulnerabilities-allowing-data-access-and-config-changes"
author: "NewsBot (Validated by Federico Sella)"
description: "أجهزة ABB EIBPORT معرضة لهجمات البرمجة النصية عبر المواقع وسرقة معرفات الجلسات. يتوفر تحديث للبرنامج الثابت إلى الإصدار 3.9.2."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03"
source: "CISA"
severity: "High"
target: "أجهزة ABB EIBPORT"
cve: "CVE-2021-22291"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

أجهزة ABB EIBPORT معرضة لهجمات البرمجة النصية عبر المواقع وسرقة معرفات الجلسات. يتوفر تحديث للبرنامج الثابت إلى الإصدار 3.9.2.

{{< cyber-report severity="High" source="CISA" target="أجهزة ABB EIBPORT" cve="CVE-2021-22291" >}}

أصدرت CISA نشرة استشارية (ICSA-26-148-03) تفصل ثغرات أمنية متعددة في أجهزة ABB EIBPORT، وتحديداً طرازي EIBPORT V3 KNX وEIBPORT V3 KNX GSM. تشمل الثغرات خللاً في البرمجة النصية عبر المواقع (XSS) (CWE-79) ومشكلة سرقة معرف الجلسة (CVE-2021-22291)، مما قد يسمح للمهاجم بالوصول إلى المعلومات الحساسة المخزنة على الجهاز وتغيير إعداداته.

{{< ad-banner >}}

إصدارات البرنامج الثابت المتأثرة هي تلك التي تسبق الإصدار 3.9.2. أصدرت ABB تحديثاً للبرنامج الثابت لمعالجة هذه الثغرات التي تم الإبلاغ عنها بشكل خاص. تُنشر المنتجات عالمياً عبر قطاعي التصنيع الحيوي وتكنولوجيا المعلومات، ويقع مقر البائع في سويسرا.

على الرغم من عدم تقديم درجة CVSS في النشرة الاستشارية، إلا أن التأثير المحتمل على سلامة الجهاز وسريته يستدعي التصحيح الفوري. يجب على المؤسسات التي تستخدم أجهزة ABB EIBPORT المتأثرة تطبيق تحديث البرنامج الثابت في أقرب وقت ممكن للتخفيف من خطر الاستغلال.

{{< netrunner-insight >}}

لمحللي SOC، أعط الأولوية لفحص أجهزة ABB EIBPORT التي تعمل بإصدار برنامج ثابت أقل من 3.9.2 وراقب أي تغييرات غير طبيعية في الإعدادات أو شذوذ في الجلسات. يجب على فرق DevSecOps دمج تحديث البرنامج الثابت هذا في خط أنابيب إدارة التصحيح، خاصة بالنظر إلى دور الجهاز في أتمتة المباني والبنية التحتية الحيوية.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03)**
