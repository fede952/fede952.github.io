---
title: "CISA تحذر من ثغرة تجاوز المصادقة الحرجة في Rockwell FactoryTalk Analytics PavilionX"
date: "2026-06-18T11:06:01Z"
original_date: "2026-06-16T12:00:00"
lang: "ar"
translationKey: "cisa-warns-of-critical-auth-bypass-in-rockwell-factorytalk-analytics-pavilionx"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA تنبه إلى CVE-2025-14272 التي تؤثر على Rockwell Automation FactoryTalk Analytics PavilionX <7.01، مما يسمح بعمليات غير مصرح بها ذات امتيازات في بيئات التصنيع الحرجة."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01"
source: "CISA"
severity: "High"
target: "Rockwell FactoryTalk Analytics PavilionX"
cve: "CVE-2025-14272"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA تنبه إلى CVE-2025-14272 التي تؤثر على Rockwell Automation FactoryTalk Analytics PavilionX <7.01، مما يسمح بعمليات غير مصرح بها ذات امتيازات في بيئات التصنيع الحرجة.

{{< cyber-report severity="High" source="CISA" target="Rockwell FactoryTalk Analytics PavilionX" cve="CVE-2025-14272" >}}

نشرت CISA تحذيرًا (ICSA-26-167-01) بشأن ثغرة نقص المصادقة في Rockwell Automation FactoryTalk Analytics PavilionX. الخلل، الذي يُتتبع باسم CVE-2025-14272، يؤثر على الإصدارات الأقدم من 7.01 ويسمح لمهاجم غير مصرح له بتنفيذ عمليات ذات امتيازات مثل إدارة المستخدمين والأدوار.

{{< ad-banner >}}

تنشأ الثغرة من ضعف تطبيق المصادقة في نقاط نهاية API. قد يؤدي الاستغلال الناجح إلى السيطرة الإدارية الكاملة على النظام المتأثر. أصدرت Rockwell Automation الإصدار 7.01 لمعالجة المشكلة، ويُحث المستخدمون على التحديث فورًا.

نظرًا لنشر هذا المنتج عبر قطاعات التصنيع الحرجة عالميًا، فإن خطر تعطيل العمليات أو اختراق البيانات كبير. يجب على المؤسسات إعطاء الأولوية للتصحيح ومراجعة ضوابط الوصول للتخفيف من احتمالية الاستغلال.

{{< netrunner-insight >}}

هذه ثغرة تجاوز مصادقة كلاسيكية يجب التعامل معها كتصحيح عالي الأولوية. يجب على محللي SOC مراقبة استدعاءات API الشاذة أو تصعيد الامتيازات في بيئات PavilionX. يجب على فرق DevSecOps التأكد من نشر الإصدار 7.01 وأن تجزئة الشبكة تحد من تعرض نقاط النهاية هذه.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01)**
