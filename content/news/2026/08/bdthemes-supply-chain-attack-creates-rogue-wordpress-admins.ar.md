---
title: "هجوم سلسلة التوريد على BdThemes ينشئ مسؤولي ووردبريس مزيفين"
date: "2026-08-11T08:10:19Z"
original_date: "2026-08-11T05:48:44"
lang: "ar"
translationKey: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
slug: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
author: "NewsBot (Validated by Federico Sella)"
description: "اختراق سلسلة التوريد يستهدف إضافات ووردبريس من BdThemes؛ لم يتم تعديل أي كود مصدري، لكن JSON خبيث ينشئ حسابات مسؤول مزيفة."
original_url: "https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html"
source: "The Hacker News"
severity: "High"
target: "مواقع ووردبريس التي تستخدم إضافات BdThemes"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

اختراق سلسلة التوريد يستهدف إضافات ووردبريس من BdThemes؛ لم يتم تعديل أي كود مصدري، لكن JSON خبيث ينشئ حسابات مسؤول مزيفة.

{{< cyber-report severity="High" source="The Hacker News" target="مواقع ووردبريس التي تستخدم إضافات BdThemes" >}}

كشف باحثو الأمن السيبراني عن هجوم على سلسلة التوريد يستهدف BdThemes، وهو مورّد إضافات ووردبريس. أدى الاختراق إلى تعطيل تنزيل الإضافات مؤقتًا من قبل فريق إضافات ووردبريس. ومن الجدير بالذكر أن الهجوم ينحرف عن حوادث سلسلة التوريد النموذجية: لم يتم تعديل أي ملفات كود مصدري داخل مستودع WordPress.org الرسمي.

{{< ad-banner >}}

بدلاً من ذلك، يستغل الهجوم حمولات JSON خبيثة لإنشاء حسابات مسؤول ووردبريس مزيفة. تسمح هذه التقنية للمهاجمين بالوصول غير المصرح به إلى المواقع المتأثرة دون تغيير ملفات الإضافات الأساسية، مما يجعل اكتشافها أكثر صعوبة لفحوصات السلامة القياسية.

سلط الباحث في Wordfence باولو تريسو الضوء على الطبيعة غير المعتادة للهجوم، مؤكدًا أن غياب تعديلات الكود المصدري يؤكد الحاجة إلى مراقبة شاملة لسلسلة التوريد تتجاوز مجرد سلامة الكود.

{{< netrunner-insight >}}

يؤكد هذا الهجوم على أهمية مراقبة ليس فقط تغييرات الكود ولكن أيضًا ملفات التكوين والبيانات مثل JSON. بالنسبة لمحللي SOC، تعامل مع تحديثات الإضافات كأحداث عالية المخاطر وتحقق من سلامة جميع الملفات، وليس فقط الكود المصدري. يجب على DevSecOps تنفيذ مراقبة وقت التشغيل لإنشاء حسابات المسؤول غير المتوقعة والنظر في مراقبة سلامة الملفات التي تغطي الأصول غير البرمجية.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html)**
