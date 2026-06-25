---
title: "ثغرات Cordyceps في CI/CD تهدد أكثر من 300 مستودع على GitHub"
date: "2026-06-25T10:14:17Z"
original_date: "2026-06-24T12:48:11"
lang: "ar"
translationKey: "cordyceps-ci-cd-flaws-threaten-300-github-repos"
author: "NewsBot (Validated by Federico Sella)"
description: "نقطة ضعف جديدة في سير عمل CI/CD تحمل الاسم الرمزي Cordyceps تسمح للمهاجمين باختطاف سير العمل واختراق سلاسل التوريد مفتوحة المصدر في المؤسسات الكبرى."
original_url: "https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html"
source: "The Hacker News"
severity: "Critical"
target: "سير عمل CI/CD على GitHub"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

نقطة ضعف جديدة في سير عمل CI/CD تحمل الاسم الرمزي Cordyceps تسمح للمهاجمين باختطاف سير العمل واختراق سلاسل التوريد مفتوحة المصدر في المؤسسات الكبرى.

{{< cyber-report severity="Critical" source="The Hacker News" target="سير عمل CI/CD على GitHub" >}}

حدد باحثو الأمن السيبراني في Novee Security نمطًا قابلاً للاستغلال بشكل خطير في سير عمل CI/CD، أطلق عليه اسم Cordyceps، يمكن أن يسمح للمهاجمين باختطاف سير العمل واختراق سلاسل التوريد مفتوحة المصدر. يؤثر هذا الخلل على أكثر من 300 مستودع على GitHub تابعة لمؤسسات كبرى بما في ذلك Microsoft وGoogle وApache.

{{< ad-banner >}}

يتيح نمط Cordyceps سيطرة كاملة للمهاجم على المستودعات، مما قد يؤدي إلى تغييرات غير مصرح بها في الكود، وإدخال أبواب خلفية، وهجمات على سلسلة التوريد في المراحل اللاحقة. ينشأ الثغرة من تكوينات سير عمل غير آمنة تفشل في عزل أو التحقق من صحة المدخلات بشكل صحيح.

يُحث المؤسسات التي تستخدم GitHub Actions أو منصات CI/CD المماثلة على مراجعة تعريفات سير العمل الخاصة بها بحثًا عن نمط Cordyceps وتنفيذ أذونات بأقل صلاحية، وتنقية المدخلات، وعزل البيئة للتخفيف من المخاطر.

{{< netrunner-insight >}}

هذا ناقل هجوم نموذجي لسلسلة التوريد. يجب على محللي SOC مراقبة عمليات سير العمل غير الطبيعية والتغييرات غير المتوقعة في المستودعات. يجب على فرق DevSecOps تدقيق تكوينات خط أنابيب CI/CD فورًا، مع التركيز على معالجة المدخلات غير الموثوقة ونطاق الأذونات.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)**
