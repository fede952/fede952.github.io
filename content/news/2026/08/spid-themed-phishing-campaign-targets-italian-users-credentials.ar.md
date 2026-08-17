---
title: "حملة تصيد احتيالي بأسلوب SPID تستهدف بيانات اعتماد المستخدمين الإيطاليين"
date: "2026-08-17T07:50:54Z"
original_date: "2026-08-03T11:05:05"
lang: "ar"
translationKey: "spid-themed-phishing-campaign-targets-italian-users-credentials"
slug: "spid-themed-phishing-campaign-targets-italian-users-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-AGID يحذر من حملة تصيد احتيالي جديدة تسيء استخدام علامتي SPID و AgID لسرقة البيانات الشخصية والمصرفية عبر نطاقات تحتوي على 'spid' و 'gov'."
original_url: "https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/"
source: "CERT-AgID"
severity: "Medium"
target: "مستخدمو SPID الإيطاليون"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-AGID يحذر من حملة تصيد احتيالي جديدة تسيء استخدام علامتي SPID و AgID لسرقة البيانات الشخصية والمصرفية عبر نطاقات تحتوي على 'spid' و 'gov'.

{{< cyber-report severity="Medium" source="CERT-AgID" target="مستخدمو SPID الإيطاليون" >}}

حدد CERT-AGID حملة تصيد احتيالي مستمرة تسيء استخدام سمة SPID (النظام العام للهوية الرقمية) للاستيلاء الاحتيالي على المعلومات الشخصية والمصرفية من المستخدمين الإيطاليين. تستغل الحملة الأسماء والشعارات الرسمية لـ AgID و SPID لتعزيز مصداقيتها، مما يجعلها خادعة بشكل خاص.

{{< ad-banner >}}

يستخدم المهاجمون نطاقات متعددة تتضمن المصطلحين 'spid' و 'gov' في أسمائها، وهي تكتيك مصمم لخداع المستخدمين وجعلهم يعتقدون أنهم يتفاعلون مع خدمات حكومية مشروعة. يستغل هذا النهج الثقة التي يضعها المستخدمون في النطاقات والعلامات التجارية ذات المظهر الرسمي.

على الرغم من أن ناقل الهجوم الدقيق (مثل البريد الإلكتروني أو الرسائل النصية) غير محدد في التقرير، فإن هدف الحملة واضح: جمع البيانات الحساسة. يُنصح المستخدمون بالتحقق من صحة أي اتصال يطلب معلومات شخصية أو مصرفية والإبلاغ عن الرسائل المشبوهة إلى السلطات المختصة.

{{< netrunner-insight >}}

لمحللي SOC، تؤكد هذه الحملة على أهمية مراقبة النطاقات المشابهة التي تجمع بين مصطلحات العلامات التجارية الموثوقة مع 'gov' أو نطاقات المستوى الأعلى المماثلة. قم بتنفيذ قواعد تصفية البريد الإلكتروني التي تشير إلى الرسائل التي تحتوي على مثل هذه النطاقات، وتثقيف المستخدمين للتحقق من عناوين URL قبل النقر. يجب على فرق DevSecOps النظر في دمج خلاصات سمعة النطاق في مجموعة الأمان الخاصة بهم لحظر نطاقات التصيد هذه تلقائيًا.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CERT-AgID ›](https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/)**
