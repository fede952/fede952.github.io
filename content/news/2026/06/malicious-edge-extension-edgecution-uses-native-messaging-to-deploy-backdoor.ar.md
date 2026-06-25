---
title: "إضافة Edge الخبيثة 'Edgecution' تستخدم المراسلة الأصلية لنشر باب خلفي"
date: "2026-06-25T10:16:09Z"
original_date: "2026-06-24T20:58:22"
lang: "ar"
translationKey: "malicious-edge-extension-edgecution-uses-native-messaging-to-deploy-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "إضافة Microsoft Edge خبيثة تُدعى 'Edgecution' تهرب من صندوق رمل المتصفح عبر المراسلة الأصلية لنشر باب خلفي قائم على Python في هجمات الفدية."
original_url: "https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/"
source: "BleepingComputer"
severity: "High"
target: "مستخدمو Microsoft Edge"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

إضافة Microsoft Edge خبيثة تُدعى 'Edgecution' تهرب من صندوق رمل المتصفح عبر المراسلة الأصلية لنشر باب خلفي قائم على Python في هجمات الفدية.

{{< cyber-report severity="High" source="BleepingComputer" target="مستخدمو Microsoft Edge" >}}

تم رصد إضافة Microsoft Edge خبيثة تُدعى 'Edgecution' في هجوم فدية، حيث تستغل واجهة برمجة تطبيقات المراسلة الأصلية للمتصفح للهروب من صندوق الرمل وتنفيذ تعليمات برمجية عشوائية على النظام المضيف. تعمل الإضافة كجسر لنشر باب خلفي قائم على Python، مما يتيح الوصول المستمر وأنشطة ضارة أخرى.

{{< ad-banner >}}

تبدأ سلسلة الهجوم بتثبيت الإضافة الضارة، التي تسيء استخدام المراسلة الأصلية للتواصل مع تطبيق أصلي خارج صندوق رمل المتصفح. تتجاوز هذه التقنية حدود أمان المتصفح النموذجية، مما يسمح للمهاجم بتنفيذ الأوامر وإسقاط حمولات إضافية، بما في ذلك برامج الفدية.

يسلط باحثو الأمن الضوء على أن هذه الطريقة خبيثة بشكل خاص لأنها تستغل ميزة متصفح شرعية، مما يجعل اكتشافها صعبًا لحلول أمان نقاط النهاية التقليدية. يُنصح المؤسسات بمراقبة إضافات المتصفح غير المصرح بها وتقييد أذونات المراسلة الأصلية حيثما أمكن.

{{< netrunner-insight >}}

يؤكد هذا الهجوم على أهمية مراقبة تثبيتات إضافات المتصفح ونشاط المراسلة الأصلية. يجب على محللي SOC البحث عن سلوكيات إضافات غير طبيعية واتصالات مضيفة أصلية غير متوقعة، بينما يجب على فرق DevSecOps فرض قوائم السماح الصارمة للإضافات وتعطيل مضيفي المراسلة الأصلية غير الضروريين.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على BleepingComputer ›](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)**
