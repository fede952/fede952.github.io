---
title: "ثغرات في Subnet Solutions PowerSYSTEM Center تسمح بتسريب المعلومات وحقن CRLF"
date: "2026-05-13T09:40:06Z"
original_date: "2026-05-12T12:00:00"
lang: "ar"
translationKey: "subnet-solutions-powersystem-center-flaws-enable-info-leak-crlf-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA تحذر من ثغرات متعددة في Subnet Solutions PowerSYSTEM Center، بما في ذلك تسريب المعلومات وحقن CRLF، تؤثر على الإصدارات من 2020 إلى 2026."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02"
source: "CISA"
severity: "High"
target: "Subnet Solutions PowerSYSTEM Center"
cve: "CVE-2026-35504"
cvss: 8.2
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA تحذر من ثغرات متعددة في Subnet Solutions PowerSYSTEM Center، بما في ذلك تسريب المعلومات وحقن CRLF، تؤثر على الإصدارات من 2020 إلى 2026.

{{< cyber-report severity="High" source="CISA" target="Subnet Solutions PowerSYSTEM Center" cve="CVE-2026-35504" cvss="8.2" >}}

أصدرت CISA نشرة استشارية (ICSA-26-132-02) تفصل ثغرات متعددة في Subnet Solutions PowerSYSTEM Center، وهي منصة تُستخدم في قطاعي التصنيع والطاقة الحيويين. تشمل الثغرات تفويضًا غير صحيح (CVE-2026-26289) يسمح للمستخدمين الموثوقين بصلاحيات محدودة بتصدير حسابات الأجهزة وكشف معلومات حساسة كانت مقصورة عادةً على المسؤولين. بالإضافة إلى ذلك، يمكن لثغرات حقن CRLF (CVE-2026-35504، CVE-2026-33570، CVE-2026-35555) تمكين المهاجمين من حقن رؤوس أو استجابات ضارة.

{{< ad-banner >}}

تغطي الإصدارات المتأثرة PowerSYSTEM Center 2020 (5.8.x إلى 5.28.x)، و2024 (6.0.x إلى 6.1.x)، و2026 (7.0.x). تحمل الثغرات درجة أساسية 8.2 وفقًا لـ CVSS v3، مما يشير إلى خطورة عالية. قد يؤدي استغلالها إلى تسريب المعلومات واحتمال التلاعب بالجلسات أو تقسيم استجابات HTTP.

نظرًا لنشر المنتج في البنية التحتية الحيوية عالميًا، يجب على المؤسسات إعطاء الأولوية لتطبيق التصحيحات. من المحتمل أن تكون Subnet Solutions قد أصدرت تحديثات؛ يُنصح المسؤولون بالاطلاع على النشرات الاستشارية الأمنية للبائع وتطبيق أحدث التصحيحات. وإلى ذلك الحين، يُقيد الوصول الشبكي إلى PowerSYSTEM Center وراقب الأنشطة الشاذة.

{{< netrunner-insight >}}

لمحللي SOC، راقب سجلات المصادقة بحثًا عن عمليات تصدير غير عادية لحسابات الأجهزة—فهذه علامة واضحة على استغلال CVE-2026-26289. يجب على فرق DevSecOps جرد إصدارات PowerSYSTEM Center فورًا وتطبيق التصحيحات، حيث يمكن ربط متجهات حقن CRLF (CVE-2026-35504 وآخرون) بهجمات أخرى لاختراق سلامة الجلسة. تعامل مع هذا كإجراء علاجي عالي الأولوية نظرًا لدرجة CVSS 8.2 والتعرض للقطاعات الحيوية.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02)**
