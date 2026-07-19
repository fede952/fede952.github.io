---
title: "ثغرة HollowByte في DoS تضخم ذاكرة خادم OpenSSL بحمولة 11 بايت"
date: "2026-07-19T09:04:58Z"
original_date: "2026-07-17T17:56:21"
lang: "ar"
translationKey: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
slug: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
author: "NewsBot (Validated by Federico Sella)"
description: "ثغرة أمنية تُعرف باسم HollowByte تسمح للمهاجمين غير الموثقين بالتسبب في حالة رفض الخدمة على خوادم OpenSSL بحمولة خبيثة تبلغ 11 بايت فقط."
original_url: "https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/"
source: "BleepingComputer"
severity: "High"
target: "خوادم OpenSSL"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ثغرة أمنية تُعرف باسم HollowByte تسمح للمهاجمين غير الموثقين بالتسبب في حالة رفض الخدمة على خوادم OpenSSL بحمولة خبيثة تبلغ 11 بايت فقط.

{{< cyber-report severity="High" source="BleepingComputer" target="خوادم OpenSSL" >}}

ثغرة أمنية مكتشفة حديثًا، تُسمى HollowByte، تمكن المهاجمين غير الموثقين من التسبب في حالة رفض الخدمة على خوادم OpenSSL عن طريق إرسال حمولة مصممة خصيصًا بحجم 11 بايت فقط. تستغل الثغرة أوجه قصور في تخصيص الذاكرة، مما يؤدي إلى تضخم ذاكرة الخادم واستنزاف الموارد المتاحة في النهاية.

{{< ad-banner >}}

لا يتطلب الهجوم توثيقًا ويمكن تنفيذه عن بُعد، مما يجعله تهديدًا كبيرًا لأي مؤسسة تعتمد على OpenSSL للاتصالات الآمنة. يسمح حجم الحمولة الصغير للمهاجمين بتضخيم تأثيرهم باستخدام نطاق ترددي محدود، مما قد يطغى على الخوادم بأقل جهد.

على الرغم من عدم تعيين معرف CVE بعد، فقد تم الإفصاح عن الثغرة لمشروع OpenSSL، ومن المتوقع إصدار تصحيحات. في غضون ذلك، يُنصح المسؤولون بمراقبة استخدام الذاكرة وتطبيق تحديد المعدل أو قواعد كشف التسلل للتخفيف من الاستغلال المحتمل.

{{< netrunner-insight >}}

لمحللي SOC، هذا ناقل DoS كلاسيكي منخفض النطاق الترددي وعالي التأثير يمكنه تجاوز دفاعات الحجم التقليدية. يجب على فرق DevSecOps إعطاء الأولوية للتصحيح بمجرد توفره والنظر في نشر تنبيهات مراقبة الذاكرة لكشف النمو الشاذ. الحمولة البالغة 11 بايت تجعل هذا مرشحًا مثاليًا للإدراج في قواعد كشف التهديدات.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/)**
