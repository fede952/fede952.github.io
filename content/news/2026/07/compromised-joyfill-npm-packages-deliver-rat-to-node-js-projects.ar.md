---
title: "حزم npm المخترقة joyfill توزع برنامج RAT على مشاريع Node.js"
date: "2026-07-29T09:34:53Z"
original_date: "2026-07-29T04:20:57"
lang: "ar"
translationKey: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
slug: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
author: "NewsBot (Validated by Federico Sella)"
description: "تحتوي الإصدارات التجريبية من @joyfill/layouts و @joyfill/components على غرسة JavaScript وقت الاستيراد تقوم بفك تشفير الكود لنشر حصان طروادة للوصول عن بُعد."
original_url: "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "مطورو Node.js الذين يستخدمون حزم joyfill"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تحتوي الإصدارات التجريبية من @joyfill/layouts و @joyfill/components على غرسة JavaScript وقت الاستيراد تقوم بفك تشفير الكود لنشر حصان طروادة للوصول عن بُعد.

{{< cyber-report severity="High" source="The Hacker News" target="مطورو Node.js الذين يستخدمون حزم joyfill" >}}

تم اختراق حزمتي npm في مساحة @joyfill، وهما @joyfill/layouts الإصدار 0.1.2-2773.beta.0 و @joyfill/components الإصدار 4.0.0-rc24-2773-beta.4. تحتوي هذه الإصدارات التجريبية على غرسة JavaScript وقت الاستيراد تقوم بفك تشفير الكود، مما يؤدي في النهاية إلى تسليم حصان طروادة للوصول عن بُعد (RAT) المرتبط بعائلة البرامج الضارة DEV#POPPER.

{{< ad-banner >}}

يتم تنفيذ الكود الخبيث عند استيراد الحزم إلى مشروع Node.js، مما يمنح المهاجمين وصولاً عن بُعد إلى النظام المخترق. يسلط الهجوم الضوء على المخاطر المستمرة لهجمات سلسلة التوريد التي تستهدف نظام npm البيئي، خاصة من خلال الإصدارات التجريبية أو إصدارات المرشح التي قد تحصل على تدقيق أقل.

يجب على المطورين الذين استخدموا هذه الإصدارات المحددة تدوير بيانات الاعتماد فورًا، وفحص مؤشرات الاختراق، ومراجعة أشجار التبعية الخاصة بهم بحثًا عن أي حزم مشبوهة أخرى. من المحتمل أن يكون سجل npm قد أزال الإصدارات الخبيثة، لكن التثبيتات الحالية لا تزال تشكل تهديدًا.

{{< netrunner-insight >}}

تؤكد هذه الحادثة على أهمية فحص الحزم قبل الإصدار وتنفيذ فحوصات سلامة التبعية. يجب على محللي SOC مراقبة الاتصالات الصادرة غير المعتادة من تطبيقات Node.js، بينما يجب على فرق DevSecOps فرض تثبيت صارم للإصدارات واستخدام أدوات مثل npm audit أو ماسحات SCA للكشف عن الحزم الخبيثة المعروفة.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html)**
