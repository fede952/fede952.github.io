---
title: "مُحمّل HollowFrame والبرمجية الخبيثة Matryoshka يستهدفان شركة محاماة"
date: "2026-08-01T09:01:20Z"
original_date: "2026-07-31T16:39:31"
lang: "ar"
translationKey: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
slug: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
author: "NewsBot (Validated by Federico Sella)"
description: "وفقًا لشركة Blackpoint Cyber، تم استخدام مُحمّل HollowFrame الجديد المكتوب بلغة Go والبرمجية الخبيثة Matryoshka المكتوبة بلغة Rust في هجوم تصيد احتيالي موجه ضد شركة محاماة."
original_url: "https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html"
source: "The Hacker News"
severity: "High"
target: "شركة محاماة"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

وفقًا لشركة Blackpoint Cyber، تم استخدام مُحمّل HollowFrame الجديد المكتوب بلغة Go والبرمجية الخبيثة Matryoshka المكتوبة بلغة Rust في هجوم تصيد احتيالي موجه ضد شركة محاماة.

{{< cyber-report severity="High" source="The Hacker News" target="شركة محاماة" >}}

كشفت Blackpoint Cyber عن سلسلة هجوم جديدة استهدفت شركة محاماة، تبدأ برسالة تصيد احتيالي موجه تخدع المستلم لتنزيل أرشيف مشفر. يحتوي الأرشيف على ملف اختصار ويندوز (LNK)، والذي عند تنفيذه يبدأ عملية إصابة متعددة المراحل.

{{< ad-banner >}}

يستغل الهجوم عائلتين من البرمجيات الخبيثة غير الموثقتين سابقًا: HollowFrame، وهو إطار عمل مُحمّل مكتوب بلغة Go، وMatryoshka، وهو باب خلفي مكتوب بلغة Rust. المُحمّل مسؤول عن توصيل الباب الخلفي، الذي يوفر للمهاجمين وصولًا عن بُعد إلى النظام المخترق.

تسلط هذه الحملة الضوء على التطور المستمر لأدوات البرمجيات الخبيثة، حيث يتبنى المهاجمون لغات متعددة المنصات مثل Go وRust لتفادي الاكتشاف وتعقيد التحليل. استخدام الأرشيفات المشفرة وملفات LNK في التصيد الاحتيالي الموجه هو تكتيك شائع، لكن الجمع بين هذه الأدوات المحددة يضيف طبقة جديدة من التعقيد.

{{< netrunner-insight >}}

يجب على محللي SOC إعطاء الأولوية لمراقبة عمليات تنفيذ ملفات LNK وتنزيل الأرشيفات من روابط البريد الإلكتروني، حيث إنها مؤشرات مبكرة على سلسلة الهجوم هذه. يجب على فرق DevSecOps النظر في حظر أو عزل تنفيذ الملفات من الأرشيفات المشفرة، والتأكد من ضبط حلول كشف والاستجابة للنقاط الطرفية (EDR) لاكتشاف ثنائيات Go وRust التي تظهر سلوك المُحمّل.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html)**
