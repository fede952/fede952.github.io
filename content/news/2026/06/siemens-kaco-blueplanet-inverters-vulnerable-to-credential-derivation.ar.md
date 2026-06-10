---
title: "محولات Siemens KACO Blueplanet عرضة لاستخلاص بيانات الاعتماد"
date: "2026-06-10T10:51:15Z"
original_date: "2026-06-09T12:00:00"
lang: "ar"
translationKey: "siemens-kaco-blueplanet-inverters-vulnerable-to-credential-derivation"
author: "NewsBot (Validated by Federico Sella)"
description: "ثغرات متعددة في محولات KACO blueplanet تسمح للمهاجمين باستخلاص بيانات الاعتماد من الأرقام التسلسلية، والحصول على وصول غير مصرح به. توصي Siemens بتحديثات."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02"
source: "CISA"
severity: "High"
target: "محولات Siemens KACO Blueplanet"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ثغرات متعددة في محولات KACO blueplanet تسمح للمهاجمين باستخلاص بيانات الاعتماد من الأرقام التسلسلية، والحصول على وصول غير مصرح به. توصي Siemens بتحديثات.

{{< cyber-report severity="High" source="CISA" target="محولات Siemens KACO Blueplanet" >}}

أصدرت CISA نشرة استشارية (ICSA-26-160-02) تفصل ثغرات متعددة في محولات Siemens KACO blueplanet. يمكن لهذه الثغرات أن تسمح للمهاجم باستخلاص بيانات الاعتماد من الرقم التسلسلي للجهاز وإساءة استخدامها للحصول على وصول غير مصرح به إلى المحول.

{{< ad-banner >}}

تغطي النشرة الاستشارية مجموعة واسعة من الطرازات المتأثرة، بما في ذلك blueplanet 100 NX3 M8 و 100 TL3 GEN2 و 105 TL3 وغيرها الكثير، مع إصدارات مدرجة كـ all/* أو إصدارات برامج ثابتة محددة أقل من 6.1.4.9. أصدرت KACO new energy GmbH تحديثات لبعض المنتجات وتستعد لإصلاحات لأخرى، وتوصي بإجراءات مضادة حيثما لا تتوفر التصحيحات بعد.

لم يتم توفير معرفات CVE أو درجات CVSS في النشرة الاستشارية. تعتبر الثغرات خطيرة بسبب احتمالية الاستغلال عن بعد مما يؤدي إلى وصول غير مصرح به للجهاز، مما قد يؤثر على البنية التحتية للطاقة الشمسية.

{{< netrunner-insight >}}

لمحللي SOC ومهندسي DevSecOps، تؤكد هذه النشرة الاستشارية على خطر بيانات الاعتماد الثابتة أو القابلة للاستخلاص في أجهزة IoT/OT. قم فوراً بجرد محولات KACO المتأثرة وتطبيق تحديثات البرامج الثابتة حيثما كانت متوفرة. بالنسبة للوحدات غير المصححة، قم بتنفيذ تجزئة الشبكة ومراقبة محاولات الوصول الشاذة كإجراءات تخفيف مؤقتة.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02)**
