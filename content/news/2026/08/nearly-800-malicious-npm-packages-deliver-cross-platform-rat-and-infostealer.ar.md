---
title: "ما يقرب من 800 حزمة npm خبيثة توزع حصان طروادة للوصول عن بُعد وسارق معلومات عبر المنصات"
date: "2026-08-08T07:43:01Z"
original_date: "2026-08-07T18:48:17"
lang: "ar"
translationKey: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
slug: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
author: "NewsBot (Validated by Federico Sella)"
description: "حملة تضم ما يقرب من 800 حزمة npm خبيثة تستخدم أسلوب التصيد الإملائي المعتمد على الذكاء الاصطناعي لتوزيع حصان طروادة للوصول عن بُعد وسارق معلومات يستهدف أنظمة Windows وMac وLinux."
original_url: "https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "مستخدمو سجل npm"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

حملة تضم ما يقرب من 800 حزمة npm خبيثة تستخدم أسلوب التصيد الإملائي المعتمد على الذكاء الاصطناعي لتوزيع حصان طروادة للوصول عن بُعد وسارق معلومات يستهدف أنظمة Windows وMac وLinux.

{{< cyber-report severity="High" source="The Hacker News" target="مستخدمو سجل npm" >}}

تم اكتشاف حملة جديدة تنشر ما يقرب من 800 حزمة خبيثة إلى سجل npm، وفقًا لتقرير صادر عن الباحث Paul في OpenSourceMalware. صُممت هذه الحزم لتوزيع حصان طروادة للوصول عن بُعد (RAT) وحمولة سارق معلومات عبر المنصات، مما يؤثر على أنظمة Windows وmacOS وLinux.

{{< ad-banner >}}

يبدو أن الحزم الخبيثة تستخدم أسماء حزم 'مقلدة إملائيًا' أو أسماء تم إنشاؤها عشوائيًا، وهي تقنية تستخدم أسماء مولدة بالذكاء الاصطناعي لتفادي الاكتشاف وخداع المطورين لتثبيتها. بمجرد التثبيت، توفر الحمولة للمهاجمين وصولًا عن بُعد وقدرة على سرقة المعلومات الحساسة من الأنظمة المخترقة.

تسلط هذه الحملة الضوء على المخاطر المستمرة لهجمات سلسلة التوريد عبر سجلات الحزم. يُنصح المطورون والمؤسسات بفحص أسماء الحزم بدقة، والتحقق من هويات الناشرين، واستخدام أدوات الفحص الأمني الآلي لاكتشاف ومنع مثل هذه الحزم الخبيثة قبل أن تسبب ضررًا.

{{< netrunner-insight >}}

لمحللي SOC ومهندسي DevSecOps، تؤكد هذه الحملة على الحاجة إلى تحقق قوي من مصدر الحزم ومراقبة وقت التشغيل. قم بتنفيذ أدوات آلية تكتشف أسماء الحزم والسلوكيات المشبوهة، وفكر في استخدام سجل خاص مع قائمة سماح صارمة. بالإضافة إلى ذلك، قم بتثقيف المطورين حول مخاطر التصيد الإملائي وشجعهم على التحقق من أسماء الحزم قبل التثبيت.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html)**
