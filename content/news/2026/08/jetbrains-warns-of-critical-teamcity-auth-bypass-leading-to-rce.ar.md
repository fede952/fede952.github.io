---
title: "JetBrains يحذر من ثغرة تجاوز المصادقة الحرجة في TeamCity تؤدي إلى تنفيذ التعليمات البرمجية عن بُعد"
date: "2026-08-03T10:38:49Z"
original_date: "2026-07-30T22:01:31"
lang: "ar"
translationKey: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
slug: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "يحذر JetBrains من ثغرة حرجة في تجاوز المصادقة في TeamCity On-Premises قد تسمح بتنفيذ التعليمات البرمجية عن بُعد. يُنصح بتطبيق التصحيح فورًا."
original_url: "https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/"
source: "BleepingComputer"
severity: "Critical"
target: "TeamCity On-Premises"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

يحذر JetBrains من ثغرة حرجة في تجاوز المصادقة في TeamCity On-Premises قد تسمح بتنفيذ التعليمات البرمجية عن بُعد. يُنصح بتطبيق التصحيح فورًا.

{{< cyber-report severity="Critical" source="BleepingComputer" target="TeamCity On-Premises" >}}

أصدرت JetBrains تحذيرًا بشأن ثغرة حرجة في تجاوز المصادقة تؤثر على TeamCity On-Premises. يمكن استغلال هذا الخلل من قبل مهاجم غير مصادق لتحقيق تنفيذ التعليمات البرمجية عن بُعد على الخادم المتأثر، مما يشكل خطرًا شديدًا على المؤسسات التي تعتمد على TeamCity في خطوط البناء والتكامل المستمر الخاصة بها.

{{< ad-banner >}}

تثير هذه الثغرة قلقًا خاصًا لأن خوادم TeamCity غالبًا ما تحتوي على كود مصدري حساس، وقطع بناء، وبيانات اعتماد، مما يجعلها أهدافًا عالية القيمة للمهاجمين. قد يؤدي الاستغلال الناجح إلى اختراق كامل للخادم وربما البنية التحتية الأوسع إذا لم يتم عزل الخادم بشكل صحيح.

يجب على المؤسسات التي تستخدم TeamCity On-Premises إعطاء الأولوية لتطبيق التحديثات الأمنية المقدمة من البائع فورًا. حتى يتم تطبيق التصحيحات، يُنصح بتقييد الوصول إلى الشبكة لخادم TeamCity ومراقبة أي نشاط مشبوه.

{{< netrunner-insight >}}

هذه ثغرة حرجة يجب التعامل معها كحالة طارئة. يجب على محللي SOC التحقق فورًا مما إذا كانت مؤسستهم تستخدم TeamCity On-Premises والتحقق من حالة التصحيح. نظرًا لاحتمال تنفيذ التعليمات البرمجية عن بُعد دون مصادقة، افترض حدوث اختراق إذا كان الخادم مكشوفًا وقم بإجراء مراجعة جنائية شاملة. يجب على فرق DevSecOps أيضًا النظر في تقسيم خوادم البناء وفرض ضوابط وصول صارمة للتخفيف من نطاق الانفجار.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على BleepingComputer ›](https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/)**
