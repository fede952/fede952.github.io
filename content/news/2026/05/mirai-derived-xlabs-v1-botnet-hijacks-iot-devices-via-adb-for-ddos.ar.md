---
title: "بوت نت xlabs_v1 المشتق من Mirai يختطف أجهزة إنترنت الأشياء عبر ADB لشن هجمات DDoS"
date: "2026-05-07T09:27:29Z"
original_date: "2026-05-06T20:21:00"
lang: "ar"
translationKey: "mirai-derived-xlabs-v1-botnet-hijacks-iot-devices-via-adb-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "يكشف الباحثون عن xlabs_v1، وهو بوت نت جديد قائم على Mirai يستغل منافذ Android Debug Bridge المكشوفة لتجنيد أجهزة إنترنت الأشياء في شبكة DDoS."
original_url: "https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html"
source: "The Hacker News"
severity: "High"
target: "أجهزة إنترنت الأشياء ذات ADB المكشوف"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

يكشف الباحثون عن xlabs_v1، وهو بوت نت جديد قائم على Mirai يستغل منافذ Android Debug Bridge المكشوفة لتجنيد أجهزة إنترنت الأشياء في شبكة DDoS.

{{< cyber-report severity="High" source="The Hacker News" target="أجهزة إنترنت الأشياء ذات ADB المكشوف" >}}

حدد باحثو الأمن السيبراني بوت نت جديدًا مشتقًا من Mirai، يعرف نفسه باسم xlabs_v1، يستهدف الأجهزة المتصلة بالإنترنت التي تعمل بـ Android Debug Bridge (ADB). يهدف البوت نت إلى تجنيد الأجهزة المخترقة في شبكة قادرة على شن هجمات حجب الخدمة الموزعة (DDoS).

{{< ad-banner >}}

تم الاكتشاف بواسطة Hunt.io بعد أن حددوا دليلاً مكشوفًا على خادم مستضاف في هولندا. يستغل البرنامج الضار ADB، وهي أداة سطر أوامر تستخدم لتصحيح أخطاء أجهزة Android، والتي غالبًا ما تُترك مكشوفة على أجهزة إنترنت الأشياء، مما يسمح للمهاجمين عن بُعد بالوصول غير المصرح به.

تسلط هذه الحملة الضوء على التهديد المستمر من متغيرات Mirai التي تستهدف أجهزة إنترنت الأشياء ضعيفة التأمين. يُنصح المؤسسات بتعطيل ADB على أجهزة الإنتاج وتقييد الوصول إلى الشبكة لمنع هذا الاختطاف.

{{< netrunner-insight >}}

لمحللي SOC، راقبوا اتصالات ADB غير المتوقعة من عناوين IP خارجية. يجب على فرق DevSecOps التأكد من تعطيل ADB في إصدارات الإنتاج وأن أجهزة إنترنت الأشياء معزولة عن الشبكات الحرجة للحد من وصول هذا البوت نت.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html)**
