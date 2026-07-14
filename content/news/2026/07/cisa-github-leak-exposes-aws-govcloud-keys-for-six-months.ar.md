---
title: "تسريب GitHub من CISA يعرض مفاتيح AWS GovCloud لمدة ستة أشهر"
date: "2026-07-14T09:01:14Z"
original_date: "2026-07-13T15:03:28"
lang: "ar"
translationKey: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
slug: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
author: "NewsBot (Validated by Federico Sella)"
description: "قام متعاون بتسريب بيانات اعتماد داخلية لـ CISA، بما في ذلك مفاتيح AWS GovCloud، على GitHub لمدة ستة أشهر. يسلط الخبراء الضوء على دروس حاسمة لفرق الأمان."
original_url: "https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/"
source: "Krebs on Security"
severity: "High"
target: "مستودع GitHub الخاص بـ CISA"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

قام متعاون بتسريب بيانات اعتماد داخلية لـ CISA، بما في ذلك مفاتيح AWS GovCloud، على GitHub لمدة ستة أشهر. يسلط الخبراء الضوء على دروس حاسمة لفرق الأمان.

{{< cyber-report severity="High" source="Krebs on Security" target="مستودع GitHub الخاص بـ CISA" >}}

كشفت وكالة الأمن السيبراني وأمن البنية التحتية (CISA) عن تسرب بيانات حيث قام متعاون بنشر عشرات من بيانات الاعتماد الداخلية عن غير قصد، بما في ذلك مفاتيح AWS GovCloud، في مستودع عام على GitHub. بقيت بيانات الاعتماد مكشوفة لمدة تقرب من ستة أشهر قبل أن يخطر KrebsOnSecurity الوكالة.

{{< ad-banner >}}

حدد تقرير ما بعد الحادث لـ CISA ثغرات في استجابتهم الأولية، مثل التأخر في الكشف وعدم وجود فحص آلي للأسرار في المستودعات العامة. يؤكد الحادث على الحاجة إلى إدارة قوية للأسرار ومراقبة مستمرة لمستودعات التعليمات البرمجية.

يوصي الخبراء بتنفيذ خطافات ما قبل الالتزام، وفحص الأسرار بانتظام، وضوابط وصول صارمة لمنع التسريبات المماثلة. يمكن أن يخفف استخدام بيانات الاعتماد المؤقتة والتدوير الآلي من تأثير المفاتيح المكشوفة.

{{< netrunner-insight >}}

هذا الحادث هو حالة نموذجية تظهر لماذا يجب دمج فحص الأسرار في خطوط أنابيب CI/CD، وليس فقط بعد الالتزام. يجب على محللي SOC إعطاء الأولوية للتنبيهات المتعلقة بتعرض المستودعات العامة، ويجب على فرق DevSecOps فرض وصول بأقل الامتيازات للمتعاقدين. أتمتة تدوير بيانات الاعتماد وفكر في استخدام أدوات مثل GitLeaks أو TruffleHog لاكتشاف التسريبات مبكرًا.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على Krebs on Security ›](https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/)**
