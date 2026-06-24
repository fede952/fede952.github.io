---
title: "LastPass يؤكد اختراق بيانات عبر هجوم سلسلة التوريد على Klue"
date: "2026-06-24T10:23:36Z"
original_date: "2026-06-23T13:58:25"
lang: "ar"
translationKey: "lastpass-confirms-data-breach-via-klue-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "كشفت LastPass أن المهاجمين سرقوا رموز OAuth من تطبيق طرف ثالث، Klue، للوصول إلى بيانات العملاء في بيئة Salesforce الخاصة بها."
original_url: "https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "بيئة LastPass Salesforce"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

كشفت LastPass أن المهاجمين سرقوا رموز OAuth من تطبيق طرف ثالث، Klue، للوصول إلى بيانات العملاء في بيئة Salesforce الخاصة بها.

{{< cyber-report severity="High" source="BleepingComputer" target="بيئة LastPass Salesforce" >}}

أكدت LastPass أن القراصنة تمكنوا من الوصول إلى بيانات العملاء من بيئة Salesforce الخاصة بها بعد سرقة رموز OAuth للشركة في هجوم سلسلة التوريد على Klue في وقت سابق من هذا الشهر. الاختراق، الذي تم الكشف عنه في 23 يونيو 2026، يسلط الضوء على مخاطر تكاملات الطرف الثالث وسرقة الرموز.

{{< ad-banner >}}

استخدم المهاجمون رموز OAuth المخترقة من Klue، وهو تطبيق طرف ثالث، للوصول غير المصرح به إلى مثيل Salesforce الخاص بـ LastPass. سمح هجوم سلسلة التوريد هذا للجهات الفاعلة الخبيثة بإخراج بيانات العملاء دون إطلاق تنبيهات المصادقة النموذجية.

تقوم LastPass بإخطار العملاء المتأثرين وقد ألغت الرموز المخترقة. كما تراجع الشركة سياسات الوصول الخاصة بالطرف الثالث لمنع وقوع حوادث مماثلة. يؤكد هذا الاختراق على أهمية مراقبة استخدام رموز OAuth وتنفيذ ضوابط وصول صارمة للخدمات المتكاملة.

{{< netrunner-insight >}}

هذه الحادثة هي مثال نموذجي لمخاطر سلسلة التوريد عبر إساءة استخدام رموز OAuth. يجب على محللي SOC إعطاء الأولوية لمراقبة استخدام الرموز غير الطبيعي وتنفيذ سياسات انتهاء صلاحية الرموز. يجب على فرق DevSecOps فرض وصول بأقل الامتيازات لتكاملات الطرف الثالث والنظر في استخدام رموز قصيرة العمر لتقليل نطاق الضرر.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على BleepingComputer ›](https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/)**
