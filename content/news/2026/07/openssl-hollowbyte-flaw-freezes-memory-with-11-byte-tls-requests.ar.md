---
title: "ثغرة HollowByte في OpenSSL تجمد الذاكرة بطلبات TLS بحجم 11 بايت"
date: "2026-07-18T08:44:53Z"
original_date: "2026-07-17T20:20:53"
lang: "ar"
translationKey: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
slug: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
author: "NewsBot (Validated by Federico Sella)"
description: "خلل في رفض الخدمة في OpenSSL، يُدعى HollowByte، يسمح للمهاجمين بتجميد ذاكرة الخادم باستخدام طلبات TLS صغيرة. فريق Red Team في Okta أبلغ عنه؛ تم إصدار الإصلاح بدون CVE."
original_url: "https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html"
source: "The Hacker News"
severity: "High"
target: "خوادم OpenSSL على أنظمة glibc"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

خلل في رفض الخدمة في OpenSSL، يُدعى HollowByte، يسمح للمهاجمين بتجميد ذاكرة الخادم باستخدام طلبات TLS صغيرة. فريق Red Team في Okta أبلغ عنه؛ تم إصدار الإصلاح بدون CVE.

{{< cyber-report severity="High" source="The Hacker News" target="خوادم OpenSSL على أنظمة glibc" >}}

ثغرة رفض خدمة مكتشفة حديثًا في OpenSSL، أطلق عليها فريق Red Team في Okta اسم HollowByte، تسمح للمهاجم باستنزاف ذاكرة الخادم باستخدام 11 بايت فقط من بيانات مصافحة TLS. يتسبب الخلل في تخصيص خادم OpenSSL غير المُصحح لما يصل إلى 131 كيلوبايت من الذاكرة لرسالة لا تصل أبدًا، وعلى الأنظمة التي تستخدم glibc، لا يتم تحرير تلك الذاكرة حتى إعادة تشغيل العملية.

{{< ad-banner >}}

أصدرت OpenSSL الإصلاح في يونيو 2026 دون تعيين معرف CVE، أو إصدار تنبيه، أو ملاحظة التغيير في سجل التغييرات. نشر فريق Red Team في Okta، الذي اكتشف وأبلغ عن الخلل، التفاصيل بعد إصدار الإصلاح. تؤثر الثغرة على خوادم OpenSSL التي تعمل على أنظمة glibc، مما يجعلها عرضة لهجمات استنزاف الذاكرة.

بينما يتطلب الهجوم فقط TLS ClientHello واحد بحجم 11 بايت، يمكن أن يكون التأثير شديدًا في البيئات التي تكون فيها عمليات OpenSSL طويلة العمر وتتعامل مع العديد من الاتصالات المتزامنة. يجب على المؤسسات التي تشغل OpenSSL على glibc إعطاء الأولوية لتطبيق تحديث يونيو 2026 لمنع حالات رفض الخدمة المحتملة.

{{< netrunner-insight >}}

هذا ناقل استنزاف موارد كلاسيكي يتجاوز الحد من المعدل التقليدي لأن حركة المرور الخبيثة تبدو مثل مصافحات TLS عادية. يجب على محللي SOC مراقبة الارتفاعات المفاجئة في استخدام الذاكرة على خوادم OpenSSL، ويجب على فرق DevSecOps التحقق من نشر تحديث OpenSSL ليونيو 2026، حتى بدون CVE. عدم وجود CVE لا يقلل من المخاطر التشغيلية—تعامل مع هذا التصحيح كأولوية عالية.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html)**
