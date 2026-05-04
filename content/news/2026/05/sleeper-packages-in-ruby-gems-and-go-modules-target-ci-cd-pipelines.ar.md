---
title: "حزم النوم في Ruby Gems ووحدات Go تستهدف خطوط CI/CD"
date: "2026-05-04T09:17:53Z"
original_date: "2026-05-01T09:43:00"
lang: "ar"
translationKey: "sleeper-packages-in-ruby-gems-and-go-modules-target-ci-cd-pipelines"
author: "NewsBot (Validated by Federico Sella)"
description: "يستخدم المهاجمون حزم النوم لتوصيل حمولات ضارة، وسرقة بيانات الاعتماد، والتلاعب بـ GitHub Actions، وإنشاء استمرارية SSH في هجمات سلسلة التوريد البرمجية."
original_url: "https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html"
source: "The Hacker News"
severity: "High"
target: "خطوط CI/CD وسلاسل التوريد البرمجية"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

يستخدم المهاجمون حزم النوم لتوصيل حمولات ضارة، وسرقة بيانات الاعتماد، والتلاعب بـ GitHub Actions، وإنشاء استمرارية SSH في هجمات سلسلة التوريد البرمجية.

{{< cyber-report severity="High" source="The Hacker News" target="خطوط CI/CD وسلاسل التوريد البرمجية" >}}

تم رصد حملة جديدة لهجمات سلسلة التوريد البرمجية تستخدم حزم النوم كقناة لدفع حمولات ضارة لاحقًا تمكن من سرقة بيانات الاعتماد، والتلاعب بـ GitHub Actions، واستمرارية SSH. نُسب النشاط إلى حساب GitHub "BufferZoneCorp" الذي نشر مجموعة من المستودعات المرتبطة بـ Ruby gems ووحدات Go ضارة.

{{< ad-banner >}}

يستغل الهجوم حزمًا تبدو غير ضارة في البداية ثم تتلقى تحديثات ضارة لاحقًا، وهي تقنية تُعرف باسم حزم "النوم" أو "التروجان". بمجرد تثبيتها في بيئات CI/CD، تسرق الحمولات بيانات الاعتماد، وتعدل سير عمل GitHub Actions، وتنشئ وصول SSH مستمرًا، مما يشكل تهديدًا كبيرًا لخطوط التطوير.

يجب على المؤسسات التي تستخدم Ruby gems أو وحدات Go من مصادر غير موثوقة تدقيق تبعياتها ومراقبة نشاط المستودعات المشبوه. تسلط الحملة الضوء على التطور المتزايد لهجمات سلسلة التوريد التي تستهدف البنية التحتية للمطورين.

{{< netrunner-insight >}}

تؤكد هذه الحملة على الحاجة إلى تثبيت صارم للتبعيات والتحقق من السلامة في خطوط CI/CD. يجب على محللي SOC مراقبة التعديلات الشاذة في GitHub Actions وإضافات مفاتيح SSH، بينما يجب على مهندسي DevSecOps تطبيق مبدأ الامتياز الأقل والنظر في استخدام بيئات بناء مؤقتة للحد من نطاق الانفجار.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html)**
