---
title: "ثغرات في أجهزة Siemens Ruggedcom ROX: قم بالتحديث إلى الإصدار 2.17.1 الآن"
date: "2026-05-15T09:41:40Z"
original_date: "2026-05-14T12:00:00"
lang: "ar"
translationKey: "siemens-ruggedcom-rox-flaws-update-to-v2-17-1-now"
author: "NewsBot (Validated by Federico Sella)"
description: "تحذر CISA من ثغرات متعددة من طرف ثالث في أجهزة Siemens Ruggedcom ROX قبل الإصدار 2.17.1. تم إدراج أكثر من 30 CVE، بما في ذلك مخاطر تنفيذ التعليمات البرمجية عن بُعد. يُنصح بالتحديث الفوري."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16"
source: "CISA"
severity: "High"
target: "أجهزة Siemens Ruggedcom ROX"
cve: "CVE-2019-13103"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تحذر CISA من ثغرات متعددة من طرف ثالث في أجهزة Siemens Ruggedcom ROX قبل الإصدار 2.17.1. تم إدراج أكثر من 30 CVE، بما في ذلك مخاطر تنفيذ التعليمات البرمجية عن بُعد. يُنصح بالتحديث الفوري.

{{< cyber-report severity="High" source="CISA" target="أجهزة Siemens Ruggedcom ROX" cve="CVE-2019-13103" >}}

تحتوي إصدارات Siemens Ruggedcom ROX قبل 2.17.1 على ثغرات متعددة من طرف ثالث، كما هو موضح في نشرة CISA ICSA-26-134-16. تشمل المنتجات المتأثرة سلسلة RUGGEDCOM ROX MX5000 وMX5000RE وRX1400. أصدرت Siemens إصدارات محدثة لمعالجة هذه المشكلات وتوصي بشدة بالترقية إلى أحدث إصدار.

{{< ad-banner >}}

تدرج النشرة أكثر من 30 CVE تمتد من 2019 إلى 2025، بما في ذلك CVE-2019-13103 وCVE-2022-2347 وCVE-2025-0395. على الرغم من عدم تقديم درجات CVSS محددة، فإن اتساع نطاق الثغرات وقديمها يشير إلى سطح هجوم كبير. ترتبط العديد من هذه الثغرات بمكونات طرف ثالث وقد تؤدي إلى تنفيذ تعليمات برمجية عن بُعد أو رفض الخدمة أو كشف المعلومات.

يجب على المؤسسات التي تستخدم أجهزة Ruggedcom ROX المتأثرة إعطاء الأولوية للتصحيح، خاصة إذا كانت الأجهزة معرضة لشبكات غير موثوقة. نظرًا للطبيعة الصناعية لهذه المنتجات، يمكن استغلال الأنظمة غير المصححة للحركة الجانبية أو تعطيل البنية التحتية الحيوية.

{{< netrunner-insight >}}

هذه حالة كلاسيكية من تراكم الديون التقنية في الأنظمة المدمجة. يجب على فرق SOC جرد جميع مثيلات Ruggedcom ROX والتحقق من إصدارات البرامج الثابتة. يجب على فرق DevSecOps دمج المسح الآلي لـ CVE في CI/CD الخاص بهم للاعتماديات من طرف ثالث. عدم وجود درجات CVSS مقلق - افترض أسوأ الحالات وعامل هذه الثغرات على أنها حرجة حتى يثبت العكس.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16)**
