---
title: "CISA تحذر من ثغرة في Siemens Opcenter RDnL عبر ActiveMQ Artemis بسبب نقص المصادقة"
date: "2026-05-17T08:59:55Z"
original_date: "2026-05-14T12:00:00"
lang: "ar"
translationKey: "cisa-warns-of-siemens-opcenter-rdnl-flaw-via-activemq-artemis-missing-auth"
author: "NewsBot (Validated by Federico Sella)"
description: "تتأثر Siemens Opcenter RDnL بثغرة CVE-2026-27446، وهي ثغرة نقص المصادقة في ActiveMQ Artemis تسمح للمهاجمين غير الموثوقين في الشبكة المجاورة بحقن الرسائل أو استخراجها."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09"
source: "CISA"
severity: "High"
target: "Siemens Opcenter RDnL"
cve: "CVE-2026-27446"
cvss: 7.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تتأثر Siemens Opcenter RDnL بثغرة CVE-2026-27446، وهي ثغرة نقص المصادقة في ActiveMQ Artemis تسمح للمهاجمين غير الموثوقين في الشبكة المجاورة بحقن الرسائل أو استخراجها.

{{< cyber-report severity="High" source="CISA" target="Siemens Opcenter RDnL" cve="CVE-2026-27446" cvss="7.1" >}}

نشرت CISA تحذيرًا (ICSA-26-134-09) يوضح ثغرة نقص المصادقة لوظيفة حرجة في Apache ActiveMQ Artemis، والتي تؤثر على Siemens Opcenter RDnL. الثغرة، المسجلة باسم CVE-2026-27446 وبتقييم CVSS v3 قدره 7.1، تسمح لمهاجم غير موثوق داخل الشبكة المجاورة بإجبار وسيط مستهدف على إنشاء اتصال اتحاد أساسي صادر إلى وسيط خادع. يمكن أن يؤدي ذلك إلى حقن رسائل في أي قائمة انتظار أو استخراج رسائل من أي قائمة انتظار عبر الوسيط الخادع.

{{< ad-banner >}}

تؤثر الثغرة على جميع إصدارات Siemens Opcenter RDnL. بينما يعتبر تأثير السلامة منخفضًا بسبب عدم وجود وظيفة التحديث التلقائي وغياب المعلومات السرية في الرسائل، إلا أن تأثير التوفر وإمكانية التلاعب بالرسائل لا يزالان كبيرين. أصدر ActiveMQ Artemis إصلاحًا، وتوصي Siemens بالتحديث إلى أحدث إصدار فورًا.

نظرًا لاستخدام القطاع الصناعي الحرج عالميًا، يجب على المؤسسات التي تستخدم Opcenter RDnL إعطاء أولوية للتصحيح. ناقل الهجوم عبر الشبكة المجاورة يقلل من التعرض المباشر لكنه لا يزال يشكل خطرًا في البيئات المقسمة. يجب على الفرق الزرقاء مراقبة اتصالات الاتحاد الأساسية غير المعتادة ونشاط الوسيط الخادع.

{{< netrunner-insight >}}

لمحللي SOC، راقبوا اتصالات الاتحاد الأساسية الصادرة غير المتوقعة من وسطاء ActiveMQ Artemis، حيث أن هذا هو المؤشر الرئيسي للاستغلال. يجب على فرق DevSecOps التحديث فورًا إلى أحدث إصدار من ActiveMQ Artemis وتقييد الوصول إلى بروتوكول Core للشبكات الموثوقة فقط. تبرز هذه الثغرة خطر نقص المصادقة في مكونات الوسيطة، حتى عندما يبدو التأثير المباشر منخفضًا.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09)**
