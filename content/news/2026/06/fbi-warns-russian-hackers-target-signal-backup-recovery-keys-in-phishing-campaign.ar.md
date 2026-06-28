---
title: "FBI يحذر من استهداف قراصنة روس لمفاتيح استرداد Signal في حملة تصيد"
date: "2026-06-28T09:56:23Z"
original_date: "2026-06-26T22:06:17"
lang: "ar"
translationKey: "fbi-warns-russian-hackers-target-signal-backup-recovery-keys-in-phishing-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "FBI وCISA يحذران من أن هجمات التصيد المرتبطة بالمخابرات الروسية تسرق الآن مفاتيح استرداد Signal، مما يتيح الوصول إلى رسائل الضحايا التاريخية."
original_url: "https://www.bleepingcomputer.com/news/security/fbi-russian-hackers-now-target-signal-backup-recovery-keys/"
source: "BleepingComputer"
severity: "High"
target: "مستخدمي Signal"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

FBI وCISA يحذران من أن هجمات التصيد المرتبطة بالمخابرات الروسية تسرق الآن مفاتيح استرداد Signal، مما يتيح الوصول إلى رسائل الضحايا التاريخية.

{{< cyber-report severity="High" source="BleepingComputer" target="مستخدمي Signal" >}}

أصدرت FBI وCISA تحذيرًا مشتركًا من أن حملة تصيد تُنسب إلى أجهزة المخابرات الروسية تطورت لاستهداف مفاتيح استرداد Signal. هذه المفاتيح، التي تُستخدم عادةً لاستعادة سجل الرسائل على جهاز جديد، يمكن سرقتها لمنح المهاجمين إمكانية الوصول إلى محادثات وجهات اتصال الضحية السابقة.

{{< ad-banner >}}

ركزت الحملة في البداية على سرقة بيانات تسجيل الدخول إلى Signal ولكنها توسعت الآن لاستخراج مفاتيح الاسترداد. يستخدم المهاجمون تقنيات الهندسة الاجتماعية، مثل دعوات مجموعة Signal المزيفة أو تنبيهات أمنية، لخداع المستخدمين للكشف عن مفاتيح الاسترداد الخاصة بهم.

يُحث المؤسسات والأفراد الذين يستخدمون Signal للاتصالات الحساسة على تفعيل إجراءات أمنية إضافية، مثل قفل التسجيل وقفل الشاشة، والتحقق من صحة أي طلبات لمفاتيح الاسترداد أو بيانات تسجيل الدخول.

{{< netrunner-insight >}}

يجب على محللي SOC مراقبة طعوم التصيد التي تنتحل صفة دعوات مجموعة Signal أو تنبيهات أمنية، حيث تُستخدم الآن لجمع مفاتيح الاسترداد. يجب على فرق DevSecOps فرض المصادقة متعددة العوامل وتوعية المستخدمين بأن الخدمات الشرعية لا تطلب أبدًا مفاتيح الاسترداد أو كلمات المرور عبر رسائل غير مرغوب فيها.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على BleepingComputer ›](https://www.bleepingcomputer.com/news/security/fbi-russian-hackers-now-target-signal-backup-recovery-keys/)**
