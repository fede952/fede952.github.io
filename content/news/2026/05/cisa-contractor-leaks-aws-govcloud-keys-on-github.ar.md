---
title: "متعهد CISA يسرب مفاتيح AWS GovCloud على GitHub"
date: "2026-05-19T10:35:27Z"
original_date: "2026-05-18T20:48:21"
lang: "ar"
translationKey: "cisa-contractor-leaks-aws-govcloud-keys-on-github"
author: "NewsBot (Validated by Federico Sella)"
description: "قام متعهد تابع لـ CISA بكشف بيانات اعتماد AWS GovCloud وتفاصيل بناء داخلية في مستودع عام على GitHub، مما يمثل واحدة من أخطر تسريبات البيانات الحكومية."
original_url: "https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/"
source: "Krebs on Security"
severity: "Critical"
target: "حسابات AWS GovCloud الخاصة بـ CISA"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

قام متعهد تابع لـ CISA بكشف بيانات اعتماد AWS GovCloud وتفاصيل بناء داخلية في مستودع عام على GitHub، مما يمثل واحدة من أخطر تسريبات البيانات الحكومية.

{{< cyber-report severity="Critical" source="Krebs on Security" target="حسابات AWS GovCloud الخاصة بـ CISA" >}}

حتى نهاية الأسبوع الماضي، احتفظ متعهد لوكالة الأمن السيبراني وأمن البنية التحتية (CISA) بمستودع عام على GitHub كشف بيانات اعتماد للعديد من حسابات AWS GovCloud ذات الامتيازات العالية وعدد كبير من أنظمة CISA الداخلية. قال خبراء الأمن إن الأرشيف العام تضمن ملفات تفصل كيفية بناء CISA واختبارها ونشرها للبرامج داخليًا، وأنه يمثل أحد أكثر تسريبات الحكومة فظاعة في التاريخ الحديث.

{{< ad-banner >}}

قد تسمح بيانات الاعتماد المكشوفة لمهاجم بالوصول إلى بيئات سحابية حساسة حكومية وأنظمة داخلية، مما قد يؤدي إلى تسرب البيانات أو مزيد من الاختراق. يسلط الحادث الضوء على مخاطر الأسرار المضمنة في المستودعات العامة، حتى من قبل متعهدي الحكومة.

{{< netrunner-insight >}}

يسلط هذا التسريب الضوء على الحاجة الماسة للفحص التلقائي للأسرار وضوابط صارمة للوصول إلى المستودعات. يجب على محللي SOC إعطاء الأولوية لمراقبة بيانات الاعتماد المكشوفة في مستودعات التعليمات البرمجية العامة، بينما يجب على فرق DevSecOps فرض سياسات إدارة الأسرار وتدوير أي مفاتيح قد تكون مخترقة فورًا.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على Krebs on Security ›](https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/)**
