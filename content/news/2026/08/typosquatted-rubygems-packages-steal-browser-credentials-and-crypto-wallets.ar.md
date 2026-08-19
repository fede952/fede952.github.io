---
title: "حزم RubyGems المخترقة إملائيًا تسرق بيانات اعتماد المتصفح ومحافظ العملات المشفرة"
date: "2026-08-19T07:36:21Z"
original_date: "2026-08-18T11:20:00"
lang: "ar"
translationKey: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
slug: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
author: "NewsBot (Validated by Federico Sella)"
description: "الباحثون يحددون 16 حزمة RubyGems مخترقة إملائيًا تنشر أداة سرقة معلومات تعمل على ويندوز، مستهدفة بيانات اعتماد المتصفح ومحافظ العملات المشفرة."
original_url: "https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html"
source: "The Hacker News"
severity: "High"
target: "مستخدمو RubyGems على ويندوز"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

الباحثون يحددون 16 حزمة RubyGems مخترقة إملائيًا تنشر أداة سرقة معلومات تعمل على ويندوز، مستهدفة بيانات اعتماد المتصفح ومحافظ العملات المشفرة.

{{< cyber-report severity="High" source="The Hacker News" target="مستخدمو RubyGems على ويندوز" >}}

كشف باحثو الأمن السيبراني عن حملة جديدة للانتحال الإملائي تستهدف مستخدمي RubyGems، وتنشر أداة سرقة معلومات تعمل على ويندوز. تم اكتشاف الحملة، التي تُعرف باسم StubMaker، في 15 أغسطس 2026 بواسطة OpenSourceMalware، وتتضمن 16 حزمة خبيثة مصممة لسرقة بيانات اعتماد المتصفح ومحافظ العملات المشفرة.

{{< ad-banner >}}

الحزم الخبيثة، التي تتضمن أسماء مثل 'ubnuler' و'ubnlder' و'ri18nr' و'reaker' و'rakier' و'orakw' و'joxn'، من المرجح أنها انتحال إملائي لأحجار كريمة شائعة، مما يخدع المطورين لتثبيتها. بمجرد تثبيتها، تقوم أداة السرقة بجمع بيانات حساسة من المتصفحات وإضافات محافظ العملات المشفرة، مما يشكل خطرًا كبيرًا على سلسلة التوريد.

تسلط هذه الحملة الضوء على التهديد المستمر للانتحال الإملائي في النظم البيئية مفتوحة المصدر. يُنصح المطورون بالتحقق من أسماء الحزم بعناية، واستخدام مصادر موثوقة، ومراقبة التبعيات المشبوهة في مشاريعهم.

{{< netrunner-insight >}}

لمحللي SOC، تؤكد هذه الحملة على الحاجة إلى مراقبة تثبيتات RubyGems غير المتوقعة والمكالمات الشبكية إلى نطاقات مشبوهة. يجب على مهندسي DevSecOps فرض تثبيت صارم للتبعيات واستخدام أدوات تفحص الحزم المنتحلة إملائيًا. بالإضافة إلى ذلك، فكر في حظر أسماء الحزم الخبيثة المعروفة وتثقيف المطورين حول مخاطر الانتحال الإملائي.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html)**
