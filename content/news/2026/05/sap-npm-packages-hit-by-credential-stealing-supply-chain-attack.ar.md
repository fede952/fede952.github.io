---
title: "هجوم على حزم npm الخاصة بـ SAP عبر سلسلة التوريد لسرقة بيانات الاعتماد"
date: "2026-05-03T08:51:39Z"
original_date: "2026-04-29T16:26:00"
lang: "ar"
translationKey: "sap-npm-packages-hit-by-credential-stealing-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "حملة تُعرف باسم 'Mini Shai-Hulud' تستهدف حزم npm المرتبطة بـ SAP ببرمجيات خبيثة لسرقة بيانات الاعتماد، مما يؤثر على حزم متعددة. يحذر باحثون من عدة شركات من مخاطر سلسلة التوريد."
original_url: "https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html"
source: "The Hacker News"
severity: "High"
target: "حزم npm المرتبطة بـ SAP"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

حملة تُعرف باسم 'Mini Shai-Hulud' تستهدف حزم npm المرتبطة بـ SAP ببرمجيات خبيثة لسرقة بيانات الاعتماد، مما يؤثر على حزم متعددة. يحذر باحثون من عدة شركات من مخاطر سلسلة التوريد.

{{< cyber-report severity="High" source="The Hacker News" target="حزم npm المرتبطة بـ SAP" >}}

كشف باحثو الأمن السيبراني عن حملة هجوم على سلسلة التوريد تستهدف حزم npm الخاصة بـ SAP. تُعرف الحملة باسم 'Mini Shai-Hulud'، وتنشر برمجيات خبيثة لسرقة بيانات الاعتماد من خلال حزم مخترقة، وفقًا لتقارير من Aikido Security وOnapsis وOX Security وSafeDep وSocket وStepSecurity وWiz.

{{< ad-banner >}}

يؤثر الهجوم على حزم npm متعددة مرتبطة بـ SAP، على الرغم من عدم الكشف عن أسماء الحزم والإصدارات المحددة. صُممت البرمجيات الخبيثة لسرقة بيانات الاعتماد، مما قد يمنح المهاجمين إمكانية الوصول إلى بيئات SAP الحساسة والأنظمة النهائية.

يسلط هذا الحادث الضوء على التهديد المتزايد لسلاسل توريد البرمجيات، خاصة للمنصات الحيوية للمؤسسات مثل SAP. يُنصح المؤسسات التي تستخدم الحزم المتأثرة بتدقيق تبعياتها وتدوير أي بيانات اعتماد قد تكون تعرضت للخطر.

{{< netrunner-insight >}}

لمحللي SOC وفرق DevSecOps، يؤكد هذا الهجوم على الحاجة إلى فحص صارم للتبعيات والتحقق من سلامة حزم npm. راقب الاتصالات الصادرة غير المعتادة من الأنظمة المرتبطة بـ SAP وفكر في تنفيذ الحماية الذاتية للتطبيقات في وقت التشغيل (RASP) لكشف سرقة بيانات الاعتماد. قم بتدوير جميع بيانات الاعتماد التي قد تكون تعرضت للخطر من خلال الحزم المخترقة فورًا.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)**
