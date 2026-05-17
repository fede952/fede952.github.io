---
title: "ثغرة في أجهزة Siemens Ruggedcom ROX تسمح بقراءة ملفات الجذر عبر حقن الوسائط"
date: "2026-05-17T09:01:07Z"
original_date: "2026-05-14T12:00:00"
lang: "ar"
translationKey: "siemens-ruggedcom-rox-flaw-allows-root-file-read-via-argument-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "تحذر CISA من ثغرة CVE-2025-40948 التي تؤثر على أجهزة Ruggedcom ROX المتعددة. يمكن لمهاجم عن بعد موثوق قراءة ملفات عشوائية بصلاحيات الجذر. قم بالتحديث إلى الإصدار 2.17.1 أو أحدث."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02"
source: "CISA"
severity: "Medium"
target: "أجهزة Siemens Ruggedcom ROX"
cve: "CVE-2025-40948"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تحذر CISA من ثغرة CVE-2025-40948 التي تؤثر على أجهزة Ruggedcom ROX المتعددة. يمكن لمهاجم عن بعد موثوق قراءة ملفات عشوائية بصلاحيات الجذر. قم بالتحديث إلى الإصدار 2.17.1 أو أحدث.

{{< cyber-report severity="Medium" source="CISA" target="أجهزة Siemens Ruggedcom ROX" cve="CVE-2025-40948" cvss="6.8" >}}

تتأثر أجهزة سلسلة Siemens Ruggedcom ROX بثغرة التحكم في الوصول غير السليم (CVE-2025-40948) التي تسمح لمهاجم عن بعد موثوق بقراءة ملفات عشوائية بصلاحيات الجذر من نظام التشغيل الأساسي. تنشأ الثغرة من التحقق غير السليم من الإدخال في واجهة JSON-RPC لخادم الويب، مما يتيح حقن الوسائط.

{{< ad-banner >}}

المنتجات التالية معرضة للخطر: RUGGEDCOM ROX MX5000، MX5000RE، RX1400، RX1500، RX1501، RX1510، RX1511، RX1512، RX1524، RX1536، وRX5000، جميعها تعمل بإصدارات أقدم من 2.17.1. أصدرت Siemens تحديثات لمعالجة المشكلة وتوصي بالتصحيح الفوري.

مع درجة CVSS v3 البالغة 6.8، تم تصنيف هذه الثغرة بمتوسط الشدة. ناقل الهجوم قائم على الشبكة، ويتطلب صلاحيات منخفضة، ولا يتطلب تفاعل المستخدم. نظرًا لقطاعات البنية التحتية الحيوية (مثل التصنيع الحرج) حيث يتم نشر هذه الأجهزة، يمكن أن يؤدي الاستغلال إلى كشف معلومات كبير.

{{< netrunner-insight >}}

لمحللي SOC: أعط أولوية لتصحيح أجهزة Ruggedcom ROX في بيئتك، خاصة تلك المعرضة للشبكات غير الموثوقة. الطبيعة الموثقة للاستغلال تقلل من المخاطر الفورية ولكنها لا تلغيها—فالمهاجمون الذين يخترقون حسابًا بصلاحيات منخفضة يمكنهم التصعيد إلى وصول كامل لملفات الجذر. يجب على فرق DevSecOps مراجعة تعزيز نقاط نهاية JSON-RPC والنظر في تجزئة الشبكة للحد من التعرض.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02)**
