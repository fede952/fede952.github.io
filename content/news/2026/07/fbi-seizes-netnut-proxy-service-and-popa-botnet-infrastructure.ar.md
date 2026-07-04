---
title: "مصادرة مكتب التحقيقات الفيدرالي لخدمة بروكسي NetNut وبنية بوت نت Popa التحتية"
date: "2026-07-04T09:20:04Z"
original_date: "2026-07-02T19:27:33"
lang: "ar"
translationKey: "fbi-seizes-netnut-proxy-service-and-popa-botnet-infrastructure"
author: "NewsBot (Validated by Federico Sella)"
description: "صادر مكتب التحقيقات الفيدرالي (FBI) نطاقات مرتبطة بـ NetNut، وهي خدمة بروكسي سكنية مرتبطة ببوت نت Popa المكون من مليوني جهاز مخترق، وذلك بعد تقرير استقصائي."
original_url: "https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/"
source: "Krebs on Security"
severity: "High"
target: "خدمة البروكسي السكنية NetNut وبوت نت Popa"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

صادر مكتب التحقيقات الفيدرالي (FBI) نطاقات مرتبطة بـ NetNut، وهي خدمة بروكسي سكنية مرتبطة ببوت نت Popa المكون من مليوني جهاز مخترق، وذلك بعد تقرير استقصائي.

{{< cyber-report severity="High" source="Krebs on Security" target="خدمة البروكسي السكنية NetNut وبوت نت Popa" >}}

صادر مكتب التحقيقات الفيدرالي، بالتنسيق مع شركاء في القطاع، مئات النطاقات المرتبطة بـ NetNut، وهي خدمة بروكسي سكنية تديرها الشركة الإسرائيلية المتداولة علنًا Alarum Technologies (NASDAQ: ALAR). يأتي هذا الإجراء بعد تقرير من KrebsOnSecurity يربط NetNut ببوت نت Popa، وهي شبكة تضم ما لا يقل عن مليوني جهاز تم اختراقها دون موافقة المستخدم.

{{< ad-banner >}}

يستغل بوت نت Popa الأجهزة المخترقة لتوجيه حركة المرور عبر بنية NetNut التحتية للبروكسي، مما يتيح أنشطة ضارة مثل حشو بيانات الاعتماد والاحتيال الإعلاني والاستيلاء على الحسابات. تؤدي هذه المصادرة إلى تعطيل كل من خدمة البروكسي وقدرات القيادة والتحكم للبوت نت.

تسلط هذه العملية الضوء على الاتجاه المتزايد لاستهداف وكالات إنفاذ القانون لخدمات البروكسي التي تسهل الجرائم الإلكترونية. يجب على المؤسسات مراجعة حركة مرور شبكاتها بحثًا عن اتصالات بالنطاقات المصادرة ومراقبة أي نشاط متبقي للبوت نت.

{{< netrunner-insight >}}

بالنسبة لمحللي مراكز العمليات الأمنية (SOC)، تؤكد هذه المصادرة على أهمية مراقبة نطاقات عناوين IP للبروكسي السكني في خلاصات استخبارات التهديدات. يجب على فرق DevSecOps تدقيق أي تكاملات مع خدمات بروكسي تابعة لجهات خارجية وضمان وجود آليات قوية لكشف البوت نت، حيث قد تستمر بقايا Popa في بنية تحتية بديلة.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على Krebs on Security ›](https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/)**
