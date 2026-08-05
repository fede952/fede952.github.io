---
title: "TP-Link يصحح 15 ثغرة في Omada ZTP تتيح سلاسل تنفيذ الأوامر عن بُعد"
date: "2026-08-05T09:37:58Z"
original_date: "2026-08-04T22:18:20"
lang: "ar"
translationKey: "tp-link-patches-15-omada-ztp-flaws-enabling-rce-chains"
slug: "tp-link-patches-15-omada-ztp-flaws-enabling-rce-chains"
author: "NewsBot (Validated by Federico Sella)"
description: "TP-Link يصلح 15 ثغرة في التزويد الصفري لمس Omada التي يمكن ربطها بثغرات سابقة لتنفيذ الأوامر عن بُعد."
original_url: "https://www.bleepingcomputer.com/news/security/tp-link-patches-omada-ztp-flaws-allowing-hackers-to-breach-networks/"
source: "BleepingComputer"
severity: "High"
target: "أجهزة شبكات Omada من TP-Link"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

TP-Link يصلح 15 ثغرة في التزويد الصفري لمس Omada التي يمكن ربطها بثغرات سابقة لتنفيذ الأوامر عن بُعد.

{{< cyber-report severity="High" source="BleepingComputer" target="أجهزة شبكات Omada من TP-Link" >}}

أصدرت TP-Link تصحيحات تعالج 15 ثغرة في آلية التزويد الصفري (ZTP) لأجهزة شبكات Omada. هذه الثغرات، إذا تم استغلالها، قد تسمح للمهاجمين باختراق البنية التحتية للشبكة، مما قد يؤدي إلى وصول غير مصرح به وحركة جانبية داخل بيئات المؤسسات.

{{< ad-banner >}}

تثير هذه الثغرات القلق بشكل خاص لأنها يمكن ربطها بثغرات تم الكشف عنها سابقًا لتحقيق تنفيذ الأوامر عن بُعد (RCE). هذا يعني أن المهاجم قد يتمكن من السيطرة الكاملة على الأجهزة المتأثرة دون الحاجة إلى وصول مادي أو بيانات اعتماد صالحة، مما يشكل خطرًا كبيرًا على المؤسسات التي تعتمد على Omada لإدارة الشبكات.

يُنصح المسؤولون بشدة بتطبيق أحدث تحديثات البرامج الثابتة فورًا. بالإضافة إلى ذلك، يُوصى بمراجعة تجزئة الشبكة وعناصر التحكم في الوصول للتخفيف من تأثير الاستغلال المحتمل، خاصة في البيئات التي يُستخدم فيها ZTP بنشاط.

{{< netrunner-insight >}}

لمحللي SOC، أعطِ الأولوية لتصحيح أجهزة Omada وراقب أي نشاط غير معتاد في ZTP، حيث قد يتم استغلال هذه الثغرات في البرية. يجب على فرق DevSecOps التعامل مع ZTP كسطح هجوم عالي الخطورة وفرض تجزئة شبكة صارمة للحد من نطاق الانفجار. نظرًا لإمكانية الربط، افترض حدوث اختراق إذا لوحظ أي حركة مرور مشبوهة وقم بإجراء تحليل جنائي شامل.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على BleepingComputer ›](https://www.bleepingcomputer.com/news/security/tp-link-patches-omada-ztp-flaws-allowing-hackers-to-breach-networks/)**
