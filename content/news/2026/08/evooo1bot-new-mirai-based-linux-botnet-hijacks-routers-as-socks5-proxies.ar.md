---
title: "Evooo1Bot: روبوت جديد قائم على Mirai يختطف أجهزة التوجيه كوكلاء SOCKS5"
date: "2026-08-16T07:24:07Z"
original_date: "2026-08-15T14:14:38"
lang: "ar"
translationKey: "evooo1bot-new-mirai-based-linux-botnet-hijacks-routers-as-socks5-proxies"
slug: "evooo1bot-new-mirai-based-linux-botnet-hijacks-routers-as-socks5-proxies"
author: "NewsBot (Validated by Federico Sella)"
description: "Evooo1Bot، وهو متغير معياري من Mirai، يستهدف البوابات المتصلة بالإنترنت، محولاً أجهزة التوجيه إلى عقد ترحيل SOCKS5 لحركة المرور الخفية."
original_url: "https://www.bleepingcomputer.com/news/security/new-evooo1bot-linux-botnet-turns-routers-into-traffic-relay-nodes/"
source: "BleepingComputer"
severity: "High"
target: "أجهزة البوابة المتصلة بالإنترنت"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Evooo1Bot، وهو متغير معياري من Mirai، يستهدف البوابات المتصلة بالإنترنت، محولاً أجهزة التوجيه إلى عقد ترحيل SOCKS5 لحركة المرور الخفية.

{{< cyber-report severity="High" source="BleepingComputer" target="أجهزة البوابة المتصلة بالإنترنت" >}}

تم رصد روبوت جديد قائم على Mirai يُدعى Evooo1Bot يستهدف أجهزة البوابة المتصلة بالإنترنت، مثل أجهزة التوجيه والأجهزة الشبكية الأخرى. البرنامج الضار معياري التصميم، مما يسمح بتحديثه بوظائف جديدة بعد الاختراق الأولي.

{{< ad-banner >}}

بمجرد الإصابة، يتم إعادة استخدام الأجهزة المخترقة كعقد ترحيل لحركة مرور SOCKS5. وهذا يمكّن مشغلي الروبوت من توجيه حركة المرور الخبيثة عبر شبكة موزعة من أجهزة التوجيه المختطفة، مما يخفي مصدر الهجمات وربما يتفادى الدفاعات القائمة على الشبكة.

يعد استخدام وكلاء SOCKS5 تطوراً ملحوظاً عن وظيفة DDoS النموذجية لـ Mirai، مما يشير إلى تحول نحو عمليات أكثر خفاءً قائمة على البروكسي. يجب على المؤسسات التأكد من تحديث أجهزة البوابة، وتغيير بيانات الاعتماد الافتراضية، وعدم تعريض واجهات الإدارة عن بُعد للإنترنت.

{{< netrunner-insight >}}

بالنسبة لمحللي SOC، يسلط هذا الضوء على أهمية مراقبة الاتصالات الصادرة غير المعتادة من الأجهزة الشبكية، حيث يمكن استخدام وكلاء SOCKS5 لنقل حركة المرور الخبيثة. يجب على فرق DevSecOps تحصين أجهزة البوابة عن طريق تعطيل الخدمات غير المستخدمة، وفرض مصادقة قوية، وتقسيم واجهات الإدارة. يعد البحث الاستباقي عن التهديدات لمتغيرات Mirai أمراً ضرورياً، حيث تستمر في التطور إلى ما هو أبعد من أدوات DDoS البسيطة.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على BleepingComputer ›](https://www.bleepingcomputer.com/news/security/new-evooo1bot-linux-botnet-turns-routers-into-traffic-relay-nodes/)**
