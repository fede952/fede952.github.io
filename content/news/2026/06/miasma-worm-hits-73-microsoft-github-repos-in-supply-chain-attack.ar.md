---
title: "دودة Miasma تصيب 73 مستودعًا لـ Microsoft على GitHub في هجوم على سلسلة التوريد"
date: "2026-06-07T09:57:27Z"
original_date: "2026-06-06T06:58:04"
lang: "ar"
translationKey: "miasma-worm-hits-73-microsoft-github-repos-in-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "تم اختراق مستودعات GitHub الخاصة بـ Microsoft عبر Azure وAzure-Samples وMicrosoft وMicrosoftDocs بواسطة دودة Miasma ذاتية التكاثر، مما أثر على 73 مستودعًا."
original_url: "https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html"
source: "The Hacker News"
severity: "High"
target: "مستودعات GitHub الخاصة بـ Microsoft"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تم اختراق مستودعات GitHub الخاصة بـ Microsoft عبر Azure وAzure-Samples وMicrosoft وMicrosoftDocs بواسطة دودة Miasma ذاتية التكاثر، مما أثر على 73 مستودعًا.

{{< cyber-report severity="High" source="The Hacker News" target="مستودعات GitHub الخاصة بـ Microsoft" >}}

توسعت حملة هجوم سلسلة التوريد ذاتية التكاثر Miasma لاستهداف مستودعات GitHub الخاصة بـ Microsoft، مما أدى إلى اختراق 73 مستودعًا عبر أربع منظمات: Azure وAzure-Samples وMicrosoft وMicrosoftDocs. تم الإبلاغ عن الحادث من قبل OpenSourceMalware، مما دفع GitHub إلى تعطيل الوصول إلى المستودعات المتضررة لاحتواء الانتشار.

{{< ad-banner >}}

يؤكد هذا الهجوم على التهديد المتزايد للبرامج الضارة ذاتية التكاثر في سلاسل توريد البرمجيات. من خلال اختراق المستودعات الموثوقة، يمكن للمهاجمين حقن تعليمات برمجية ضارة في المشاريع النهائية التي تعتمد على هذه المصادر، مما قد يؤثر على مجموعة واسعة من المستخدمين والمؤسسات.

بينما تظل التفاصيل التقنية المحددة للاختراق غير معلنة، يسلط الحادث الضوء على الحاجة إلى تعزيز الإجراءات الأمنية في خطوط أنابيب CI/CD وإدارة المستودعات. يجب على المؤسسات مراجعة تبعياتها على مستودعات GitHub الخاصة بـ Microsoft ومراقبة أي نشاط غير طبيعي.

{{< netrunner-insight >}}

لمحللي SOC، أعط الأولوية لمراقبة الالتزامات غير المعتادة أو أنماط الوصول في منظمات GitHub الخاصة بك. يجب على فرق DevSecOps فرض قواعد حماية الفروع الصارمة، وطلب الالتزامات الموقعة، وتنفيذ الفحص الآلي للبرامج الضارة ذاتية التكاثر في خطوط أنابيب CI/CD. هذا الحادث هو تذكير صارخ بأنه حتى البائعين الكبار مثل Microsoft ليسوا محصنين ضد هجمات سلسلة التوريد.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html)**
