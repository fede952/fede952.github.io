---
title: "ثغرة في مكدس ABB IEC 61850 تتيح هجمات حجب الخدمة على أنظمة التحكم الصناعية"
date: "2026-05-01T09:03:14Z"
original_date: "2026-04-30T12:00:00"
lang: "ar"
translationKey: "abb-iec-61850-stack-flaw-enables-dos-on-industrial-control-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "تحذر CISA من ثغرة تم الإبلاغ عنها بشكل خاص في تنفيذ ABB لبروتوكول IEC 61850 MMS والذي يؤثر على منتجات System 800xA و Symphony Plus، مما يؤدي إلى أعطال في الأجهزة وحجب الخدمة."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01"
source: "CISA"
severity: "High"
target: "ABB System 800xA, Symphony Plus IEC 61850"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تحذر CISA من ثغرة تم الإبلاغ عنها بشكل خاص في تنفيذ ABB لبروتوكول IEC 61850 MMS والذي يؤثر على منتجات System 800xA و Symphony Plus، مما يؤدي إلى أعطال في الأجهزة وحجب الخدمة.

{{< cyber-report severity="High" source="CISA" target="ABB System 800xA, Symphony Plus IEC 61850" >}}

أصدرت CISA نشرة استشارية (ICSA-26-120-01) بشأن ثغرة في تنفيذ ABB لمكدس اتصالات IEC 61850 لتطبيقات عميل MMS. تؤثر الثغرة على العديد من المنتجات في خطي System 800xA و Symphony Plus، بما في ذلك AC800M CI868 و Symphony Plus SD Series CI850 و PM 877 و S+ Operations. يتطلب استغلال الثغرة وصولاً مسبقاً إلى شبكة IEC 61850 في الموقع.

{{< ad-banner >}}

يؤدي الاستغلال الناجح إلى حدوث عطل في الجهاز على وحدات PM 877 و CI850 و CI868، مما يستلزم إعادة تشغيل يدوية. بالنسبة لعقد S+ Operations، يؤدي الهجوم إلى تعطل برنامج تشغيل اتصالات IEC 61850، مما يؤدي إلى حالة حجب الخدمة إذا تكرر الهجوم. ومع ذلك، تظل توفر العقدة ووظائفها غير متأثرة، ولا يتأثر اتصال بروتوكول GOOSE. كما أن System 800xA IEC61850 Connect ليس عرضة للخطر.

تتأثر إصدارات البرامج الثابتة عبر عدة فروع، بما في ذلك S+ Operations حتى الإصدار 6.2.0006.0 وإصدارات مختلفة من PM 877. لم يتم توفير معرف CVE أو درجة CVSS في النشرة الاستشارية. يجب على المؤسسات التي تستخدم هذه المنتجات مراجعة النشرة وتطبيق الإجراءات التخفيفية، مثل تجزئة الشبكة وضوابط الوصول، للحد من التعرض لشبكة IEC 61850.

{{< netrunner-insight >}}

تؤكد هذه الثغرة على أهمية تجزئة الشبكة في بيئات التشغيل (OT). نظراً لأن الاستغلال يتطلب الوصول إلى شبكة IEC 61850، فإن عزل تلك الشبكة عن شبكة تكنولوجيا المعلومات المؤسسية والإنترنت أمر بالغ الأهمية. يجب على محللي SOC مراقبة حركة مرور IEC 61850 غير الطبيعية، بينما يجب على مهندسي DevSecOps إعطاء الأولوية للتصحيح والنظر في تنفيذ كشف التسلل لشذوذ بروتوكول MMS.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01)**
