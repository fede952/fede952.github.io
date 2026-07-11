---
title: "حصان طروادة MODBEACON الجديد يستخدم بث gRPC لحركة مرور C2 مشفرة"
date: "2026-07-11T08:43:59Z"
original_date: "2026-07-10T13:15:23"
lang: "ar"
translationKey: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
slug: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "مجموعة Silver Fox المرتبطة بالصين تنشر حصان طروادة MODBEACON المبني على Rust عبر تسمم SEO، باستخدام بث gRPC لاتصالات C2 المشفرة."
original_url: "https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html"
source: "The Hacker News"
severity: "High"
target: "مستخدمو Windows عبر مثبتات مزيفة"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

مجموعة Silver Fox المرتبطة بالصين تنشر حصان طروادة MODBEACON المبني على Rust عبر تسمم SEO، باستخدام بث gRPC لاتصالات C2 المشفرة.

{{< cyber-report severity="High" source="The Hacker News" target="مستخدمو Windows عبر مثبتات مزيفة" >}}

تم نسب مجموعة الجريمة الإلكترونية Silver Fox المرتبطة بالصين إلى حصان طروادة جديد للوصول عن بعد (RAT) مبني على Rust يُدعى MODBEACON. يستخدم البرنامج الضار بث gRPC لحركة مرور القيادة والتحكم (C2) المشفرة، مما يجعل الكشف أكثر صعوبة.

{{< ad-banner >}}

وفقًا لشركة الأمن السيبراني الصينية QiAnXin، تنشر Silver Fox برنامج MODBEACON عبر مثبتات مزيفة باستخدام تقنيات تسمم SEO. بينما قد تظهر المجموعة كعملية منخفضة التعقيد وعالية النشاط، إلا أن قدراتها التنظيمية الحقيقية أكثر تقدمًا.

يمثل استخدام بث gRPC لاتصالات C2 تقنية جديدة للبرامج الضارة، حيث يستفيد من HTTP/2 وبروتوكول التخزين المؤقت للاندماج مع حركة المرور المشروعة. يجب على فرق الأمن مراقبة حركة gRPC غير المعتادة والتحقيق في مواقع التنزيل المسمومة بـ SEO.

{{< netrunner-insight >}}

يجب على محللي SOC إضافة تحليل حركة مرور gRPC إلى خطوط الكشف الخاصة بهم، حيث أن استخدام MODBEACON لـ RPCs المتدفقة يمكن أن يتجاوز التوقيعات الشبكية التقليدية. يجب على فرق DevSecOps التحقق من سلامة تنزيلات البرامج والنظر في حظر نطاقات تسمم SEO المعروفة. يؤكد هذا RAT على الحاجة إلى الصيد الاستباقي للتهديدات ضد البرامج الضارة القائمة على Rust.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html)**
