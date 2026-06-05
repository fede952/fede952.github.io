---
title: "ثغرة في Hitachi Energy ITT600 Explorer تسمح بهجمات حجب الخدمة عبر عيوب libexpat"
date: "2026-06-05T10:44:09Z"
original_date: "2026-06-04T12:00:00"
lang: "ar"
translationKey: "hitachi-energy-itt600-explorer-vulnerable-to-dos-via-libexpat-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "تحذر CISA من ثغرتين في Hitachi Energy ITT600 Explorer قد تسمحان بهجمات حجب الخدمة. تؤثر على الإصدارات السابقة لـ 2.1 SP6."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02"
source: "CISA"
severity: "High"
target: "Hitachi Energy ITT600 Explorer"
cve: "CVE-2024-8176"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تحذر CISA من ثغرتين في Hitachi Energy ITT600 Explorer قد تسمحان بهجمات حجب الخدمة. تؤثر على الإصدارات السابقة لـ 2.1 SP6.

{{< cyber-report severity="High" source="CISA" target="Hitachi Energy ITT600 Explorer" cve="CVE-2024-8176" cvss="7.5" >}}

كشفت Hitachi Energy عن ثغرات في منتجها ITT600 Explorer، وتحديداً في الإصدارات السابقة لـ 2.1 SP6. تتضمن الثغرتان، المُحددتان بـ CVE-2024-8176 و CVE-2025-59375، تكراراً غير متحكم فيه وتخصيصاً للموارد دون حدود أو تقييد. يمكن استغلال هذه المشكلات للتسبب في حالة حجب خدمة.

{{< ad-banner >}}

توجد الثغرات في مكتبة libexpat المستخدمة في وظيفة IEC61850. يمكن لمهاجم لديه وصول محلي إرسال رسالة IEC61850 مصممة خصيصاً لإحداث تجاوز في سعة المكدس، مما قد يؤدي إلى تلف في الذاكرة بالإضافة إلى حجب الخدمة. من المهم أن المنتج المتأثر هو فقط ITT600 Explorer؛ نقاط نهاية نظام IEC 61850 تبقى غير متأثرة.

توصي CISA باتخاذ إجراء فوري لتطبيق التخفيفات أو التحديثات. يُستخدم المنتج عالمياً في قطاع الطاقة، وقد يؤدي استغلاله إلى تعطيل عمليات البنية التحتية الحيوية. يجب على المؤسسات التي تستخدم الإصدارات المتأثرة إعطاء أولوية للتصحيح ومراجعة النشرة للحصول على خطوات الإصلاح التفصيلية.

{{< netrunner-insight >}}

لمحللي SOC، راقبوا أنماط حركة مرور IEC61850 غير المعتادة التي قد تشير إلى محاولات استغلال. يجب على فرق DevSecOps إعطاء أولوية لتحديث ITT600 Explorer إلى الإصدار 2.1 SP6 أو أحدث، والنظر في تجزئة الشبكة للحد من الوصول المحلي للأداة. نظراً لدرجة CVSS البالغة 7.5 واحتمال تلف الذاكرة، تعامل مع هذا كتصحيح عالي الأولوية.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02)**
