---
title: "DragonForce يستخدم مرحلات Microsoft Teams لإخفاء حركة مرور C2 الخاصة بـ Backdoor.Turn"
date: "2026-06-19T11:15:07Z"
original_date: "2026-06-18T13:30:07"
lang: "ar"
translationKey: "dragonforce-uses-microsoft-teams-relays-to-hide-backdoor-turn-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "مجموعة برامج الفدية DragonForce تنشر أداة الوصول عن بُعد المخصصة Backdoor.Turn المبنية بلغة Go، مخفية حركة مرور C2 داخل مرحلات Microsoft Teams، مستهدفة شركة خدمات أمريكية كبرى."
original_url: "https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html"
source: "The Hacker News"
severity: "High"
target: "شركة خدمات أمريكية كبرى"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

مجموعة برامج الفدية DragonForce تنشر أداة الوصول عن بُعد المخصصة Backdoor.Turn المبنية بلغة Go، مخفية حركة مرور C2 داخل مرحلات Microsoft Teams، مستهدفة شركة خدمات أمريكية كبرى.

{{< cyber-report severity="High" source="The Hacker News" target="شركة خدمات أمريكية كبرى" >}}

لوحظ أن جهات تهديد مرتبطة بمجموعة برامج الفدية DragonForce تستخدم أداة وصول عن بُعد مخصصة (RAT) مبنية بلغة Go تُدعى Backdoor.Turn لإخفاء حركة مرور القيادة والتحكم (C2) داخل البنية التحتية لمرحلات Microsoft Teams. تم نشر الباب الخلفي ضد شركة خدمات أمريكية كبرى، وفقًا لنتائج من Broadcom-owned Symantec و Carbon Black.

{{< ad-banner >}}

من خلال استغلال مرحلات Microsoft Teams المشروعة، يمكن للمهاجمين مزج حركة المرور الخبيثة مع اتصالات الأعمال العادية، مما يجعل الكشف أكثر صعوبة لمدافعي الشبكة. توفر أداة RAT المبنية بلغة Go للمهاجمين وصولاً مستمرًا وقدرة على تنفيذ الأوامر، وسرقة البيانات، ونشر حمولات إضافية.

تسلط هذه التقنية الضوء على تطور تكتيكات مجموعات برامج الفدية لتجنب أدوات مراقبة الشبكة التقليدية. يجب على المؤسسات التي تستخدم Microsoft Teams مراجعة تكوينات الأمان الخاصة بها ومراقبة أنماط حركة المرور غير الطبيعية في المرحلات.

{{< netrunner-insight >}}

يجب على محللي SOC مراقبة حركة مرور مرحلات Microsoft Teams غير العادية، خاصة من نقاط النهاية غير القياسية أو خارج ساعات العمل. يجب على فرق DevSecOps فرض قوائم السماح الصارمة للتطبيقات وفحص حركة مرور Teams بحثًا عن أنفاق مشفرة قد تشير إلى اتصال C2. يؤكد هذا الهجوم على الحاجة إلى مبادئ الثقة الصفرية حتى لمنصات التعاون الموثوقة.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html)**
