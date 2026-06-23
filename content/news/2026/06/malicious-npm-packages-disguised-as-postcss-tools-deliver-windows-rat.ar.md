---
title: "حزم npm ضارة تتنكر كأدوات PostCSS لتوصيل حصان طروادة للتحكم عن بعد في ويندوز"
date: "2026-06-23T10:35:14Z"
original_date: "2026-06-23T08:54:32"
lang: "ar"
translationKey: "malicious-npm-packages-disguised-as-postcss-tools-deliver-windows-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "تم اكتشاف ثلاث حزم npm ضارة تتظاهر بأنها أدوات PostCSS تقوم بتوصيل حصان طروادة للتحكم عن بعد في ويندوز. يحث الباحثون على توخي الحذر عند تثبيت حزم npm."
original_url: "https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html"
source: "The Hacker News"
severity: "High"
target: "مستخدمو npm، أنظمة ويندوز"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تم اكتشاف ثلاث حزم npm ضارة تتظاهر بأنها أدوات PostCSS تقوم بتوصيل حصان طروادة للتحكم عن بعد في ويندوز. يحث الباحثون على توخي الحذر عند تثبيت حزم npm.

{{< cyber-report severity="High" source="The Hacker News" target="مستخدمو npm، أنظمة ويندوز" >}}

حدد باحثو الأمن السيبراني ثلاث حزم npm ضارة—aes-decode-runner-pro وpostcss-minify-selector وpostcss-minify-selector-parser—مصممة لتوصيل حصان طروادة للتحكم عن بعد (RAT) يعمل على ويندوز. تم نشر الحزم خلال الشهر الماضي بواسطة مستخدم npm وقد جمعت إجمالي 1,016 عملية تنزيل، مما يشير إلى توزيع معتدل ولكنه مقلق.

{{< ad-banner >}}

تتنكر الحزم كأدوات PostCSS الشرعية، وهي معالج CSS شائع، لخداع المطورين لتثبيتها. بمجرد التثبيت، ينفذ الكود الخبيث حمولة تؤسس وصولاً عن بعد إلى جهاز ويندوز المصاب، مما قد يسمح للمهاجمين بتسريب البيانات أو تثبيت برامج ضارة إضافية أو التنقل داخل الشبكة.

يسلط هذا الحادث الضوء على التهديد المستمر للانتحال الكتابي والخلط في التبعيات في نظام npm البيئي. يُنصح المطورون بالتحقق من أسماء الحزم بعناية، ومراجعة الكود المصدري قبل التثبيت، واستخدام أدوات التحقق من سلامة الحزم للتخفيف من هذه المخاطر.

{{< netrunner-insight >}}

لمحللي SOC ومهندسي DevSecOps، هذا تذكير بفرض فحوصات صارمة لمصدر الحزم ومراقبة تثبيتات npm غير العادية. ضع في اعتبارك تنفيذ فحص آلي للحزم الضارة المعروفة وتوعية المطورين بمخاطر الثقة العمياء في أسماء الحزم. يشير عدد التنزيلات المنخفض نسبياً إلى أن هذه الحملة قد تكون في مرحلة مبكرة، لذا فإن البحث الاستباقي عن حزم مماثلة له ما يبرره.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html)**
