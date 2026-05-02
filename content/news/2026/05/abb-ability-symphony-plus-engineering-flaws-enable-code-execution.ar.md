---
title: "ثغرات في ABB Ability Symphony Plus Engineering تتيح تنفيذ الأكواد"
date: "2026-05-02T08:20:38Z"
original_date: "2026-04-30T12:00:00"
lang: "ar"
translationKey: "abb-ability-symphony-plus-engineering-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "تحذر CISA من ثغرات في ABB Ability Symphony Plus Engineering بسبب استخدام PostgreSQL قديم، مما يسمح بتنفيذ أكواد عشوائية على الأنظمة المتأثرة."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06"
source: "CISA"
severity: "High"
target: "ABB Ability Symphony Plus Engineering"
cve: "CVE-2023-5869"
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تحذر CISA من ثغرات في ABB Ability Symphony Plus Engineering بسبب استخدام PostgreSQL قديم، مما يسمح بتنفيذ أكواد عشوائية على الأنظمة المتأثرة.

{{< cyber-report severity="High" source="CISA" target="ABB Ability Symphony Plus Engineering" cve="CVE-2023-5869" cvss="8.8" >}}

أصدرت CISA نشرة (ICSA-26-120-06) تفصل ثغرات متعددة في ABB Ability Symphony Plus Engineering، ناتجة عن استخدام PostgreSQL الإصدار 13.11 والإصدارات الأقدم. تشمل الثغرات تجاوز السعة الصحيحة، وحقن SQL، وسباق TOCTOU، وأخطاء إسقاط الامتيازات، مما قد يسمح لمهاجم مصادق بتنفيذ أكواد عشوائية على النظام.

{{< ad-banner >}}

تتراوح الإصدارات المتأثرة من Ability Symphony Plus 2.2 حتى 2.4 SP2 RU1. وتثير الثغرات قلقًا خاصًا نظرًا لنشر المنتج عبر قطاعات البنية التحتية الحيوية مثل الكيماويات والتصنيع الحرج والطاقة والمياه والصرف الصحي عالميًا.

أبرز الثغرات، CVE-2023-5869، تحمل درجة CVSS 8.8 وتتضمن تجاوز سعة صحيحة يمكن تفعيلها بواسطة بيانات مصممة من مستخدم PostgreSQL مصادق. قد يؤدي الاستغلال الناجح إلى اختراق كامل للنظام، مما يؤكد الحاجة إلى التصحيح الفوري.

{{< netrunner-insight >}}

تؤكد هذه النشرة على خطر الاعتماديات القديمة في بيئات OT. يجب على محللي SOC إعطاء الأولوية لاكتشاف الأصول الخاصة بـ ABB Symphony Plus والتأكد من تحديث PostgreSQL إلى ما بعد 13.11. يجب على فرق DevSecOps دمج فحص الاعتماديات في خطوط CI/CD لأنظمة التحكم الصناعية لالتقاط هذه الثغرات الموروثة مبكرًا.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06)**
