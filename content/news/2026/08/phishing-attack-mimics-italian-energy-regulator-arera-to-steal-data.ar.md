---
title: "هجوم تصيد يحاكي هيئة الطاقة الإيطالية ARERA لسرقة البيانات"
date: "2026-08-17T07:49:27Z"
original_date: "2026-08-05T13:20:37"
lang: "ar"
translationKey: "phishing-attack-mimics-italian-energy-regulator-arera-to-steal-data"
slug: "phishing-attack-mimics-italian-energy-regulator-arera-to-steal-data"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-AGID يحذر من موقع احتيالي ينتحل صفة ARERA، مستخدماً المكافأة الاجتماعية للمياه كطعم لجمع البيانات الشخصية والمالية عبر التصيد الاحتيالي."
original_url: "https://cert-agid.gov.it/news/phishing-ai-danni-di-arera-utilizza-il-tema-bonus-sociale-idrico/"
source: "CERT-AgID"
severity: "Medium"
target: "المواطنون الإيطاليون ومستخدمو ARERA"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-AGID يحذر من موقع احتيالي ينتحل صفة ARERA، مستخدماً المكافأة الاجتماعية للمياه كطعم لجمع البيانات الشخصية والمالية عبر التصيد الاحتيالي.

{{< cyber-report severity="Medium" source="CERT-AgID" target="المواطنون الإيطاليون ومستخدمو ARERA" >}}

حدد CERT-AGID موقعاً إلكترونياً احتيالياً يقلد اسم وشعار ARERA، الهيئة الإيطالية لتنظيم الطاقة والشبكات والبيئة. يستدرج الموقع الضحايا بوعد استرداد متعلق بـ 'المكافأة الاجتماعية للمياه'، وهو إجراء مشروع يهدف إلى تخفيض تكاليف إمدادات المياه للأسر التي تعاني من ضائقة اقتصادية أو جسدية.

{{< ad-banner >}}

تستخدم حملة التصيد تقنيات typosquatting لزيادة مصداقية النطاق المزيف، مما يجعله يبدو مطابقاً تقريباً لموقع ARERA الرسمي. الهدف هو خداع المستخدمين للكشف عن معلومات شخصية ومالية، والتي يمكن استخدامها بعد ذلك لسرقة الهوية أو الاحتيال المالي.

تسلط هذه الحادثة الضوء على التهديد المستمر لحملات التصيد التي تستغل الهيئات الحكومية أو التنظيمية المعروفة. يُنصح المستخدمون بالتحقق من صحة أي اتصال يدعي تقديم استردادات أو مكافآت، وتجنب النقر على الروابط في الرسائل أو البريد الإلكتروني غير المرغوب فيه.

{{< netrunner-insight >}}

بالنسبة لمحللي SOC، تؤكد هذه الحملة على ضرورة مراقبة النطاقات المشابهة المتعلقة بالخدمات العامة الحيوية. يمكن أن يخفف تطبيق تصفية DNS وتثقيف المستخدمين حول التحقق من القنوات الرسمية من هذه التهديدات. يجب على فرق DevSecOps النظر في دمج خلاصات استخبارات التهديدات التي تتعقب النطاقات المشابهة لحظر الوصول بشكل استباقي.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CERT-AgID ›](https://cert-agid.gov.it/news/phishing-ai-danni-di-arera-utilizza-il-tema-bonus-sociale-idrico/)**
