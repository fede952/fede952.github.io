---
title: "بوت نت RustDuck يختطف أجهزة التوجيه والكاميرات لشن هجمات حجب الخدمة"
date: "2026-07-01T10:41:08Z"
original_date: "2026-06-30T17:45:25"
lang: "ar"
translationKey: "rustduck-botnet-hijacks-routers-cameras-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "عائلة برمجيات خبيثة جديدة ذات مرحلتين تُدعى RustDuck تختطف أجهزة التوجيه المنزلية وكاميرات IP وصناديق Android والخوادم ضعيفة الحماية لبناء شبكة حجب خدمة، تم تتبعها منذ فبراير 2026."
original_url: "https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html"
source: "The Hacker News"
severity: "High"
target: "أجهزة التوجيه، كاميرات IP، صناديق Android، الخوادم"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

عائلة برمجيات خبيثة جديدة ذات مرحلتين تُدعى RustDuck تختطف أجهزة التوجيه المنزلية وكاميرات IP وصناديق Android والخوادم ضعيفة الحماية لبناء شبكة حجب خدمة، تم تتبعها منذ فبراير 2026.

{{< cyber-report severity="High" source="The Hacker News" target="أجهزة التوجيه، كاميرات IP، صناديق Android، الخوادم" >}}

يتتبع باحثون في XLab التابع لـ QiAnXin عائلة برمجيات خبيثة جديدة ذات مرحلتين تُدعى RustDuck منذ فبراير 2026. يختطف البوت نت أجهزة التوجيه المنزلية وكاميرات IP وصناديق Android والخوادم ضعيفة الحماية، ويضمها في شبكة مصممة لإسقاط المواقع والخدمات عبر الإنترنت عن طريق هجمات حجب الخدمة.

{{< ad-banner >}}

تتميز البرمجية الخبيثة بأنها أعيد بناؤها بلغة Rust، وهي لغة آمنة للذاكرة تعقد التحليل والهندسة العكسية. على الرغم من أن حجم البوت نت الحالي ليس ضخمًا، إلا أن تطوره السريع وقابليته للتكيف يشكلان تهديدًا متزايدًا للبنية التحتية للإنترنت.

يمثل RustDuck تحولًا في تطوير البوت نت، مستفيدًا من أداء Rust وميزات الأمان لإنشاء برمجيات خبيثة أكثر مرونة وأصعب في الكشف. الهدف النهائي هو بناء شبكة حجب خدمة قوية قادرة على إسقاط أهداف رئيسية.

{{< netrunner-insight >}}

لمحللي SOC: راقب حركة المرور الصادرة غير المعتادة من أجهزة IoT وأجهزة التوجيه، حيث قد تتجنب إصابة RustDuck ذات المرحلتين التوقيعات التقليدية. يجب على فرق DevSecOps فرض تقسيم الشبكة بشكل صارم وتعطيل الخدمات غير الضرورية على الأجهزة المكشوفة لتقليل سطح الهجوم.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html)**
