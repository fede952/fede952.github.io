---
title: "باب خلفي جديد لنظام لينكس يُدعى PamDOORa يسرق بيانات اعتماد SSH عبر PAM"
date: "2026-05-09T08:29:08Z"
original_date: "2026-05-08T08:41:00"
lang: "ar"
translationKey: "new-pamdoora-linux-backdoor-steals-ssh-credentials-via-pam"
author: "NewsBot (Validated by Federico Sella)"
description: "باب خلفي جديد لنظام لينكس يُدعى PamDOORa، يُباع في منتدى إجرامي روسي مقابل 1600 دولار، يستخدم وحدات PAM لتوفير وصول دائم عبر SSH باستخدام كلمة مرور سحرية ومزيج من منافذ TCP."
original_url: "https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html"
source: "The Hacker News"
severity: "High"
target: "خوادم SSH لنظام لينكس"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

باب خلفي جديد لنظام لينكس يُدعى PamDOORa، يُباع في منتدى إجرامي روسي مقابل 1600 دولار، يستخدم وحدات PAM لتوفير وصول دائم عبر SSH باستخدام كلمة مرور سحرية ومزيج من منافذ TCP.

{{< cyber-report severity="High" source="The Hacker News" target="خوادم SSH لنظام لينكس" >}}

كشف باحثون في مجال الأمن السيبراني عن باب خلفي جديد لنظام لينكس يُدعى PamDOORa، تم الإعلان عنه في منتدى Rehub الإجرامي الروسي مقابل 1600 دولار من قبل جهة تهديد تُعرف باسم 'darkworm'. صُمم الباب الخلفي كمجموعة أدوات ما بعد الاستغلال تعتمد على وحدة المصادقة القابلة للتوصيل (PAM)، مما يتيح وصولاً دائماً عبر SSH من خلال مزيج من كلمة مرور سحرية ومنفذ TCP محدد.

{{< ad-banner >}}

يعمل PamDOORa عن طريق اعتراض مصادقة SSH عبر وحدات PAM الخبيثة، مما يسمح للمهاجمين بتجاوز بيانات الاعتماد العادية والحصول على وصول غير مصرح به. استخدام وحدات PAM يجعل الباب الخلفي خفيًا، حيث يندمج في تدفق المصادقة القياسي لنظام لينكس.

يُسلط بيع هذه الأدوات في منتديات الجرائم الإلكترونية الضوء على تسليع أدوات الهجوم المتطورة. يُنصح المؤسسات بمراقبة أنماط مصادقة SSH غير المعتادة وضمان مراجعة تكوينات PAM بانتظام.

{{< netrunner-insight >}}

بالنسبة لمحللي SOC، يتطلب اكتشاف PamDOORa مراقبة اتصالات SSH غير المتوقعة على منافذ غير قياسية وربطها بتغييرات وحدات PAM. يجب على فرق DevSecOps فرض إدارة صارمة لتكوين PAM والنظر في مراقبة سلامة الملفات لـ /etc/pam.d/ والمكتبات ذات الصلة. يؤكد هذا الباب الخلفي على أهمية التعامل مع PAM كحدود أمنية حرجة.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html)**
