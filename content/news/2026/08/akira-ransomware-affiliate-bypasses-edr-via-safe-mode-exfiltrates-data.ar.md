---
title: "عضو في عصابة أkira للفدية يتجاوز أنظمة كشف الاستجابة الطرفية عبر الوضع الآمن ويسرق البيانات"
date: "2026-08-16T07:35:41Z"
original_date: "2026-08-13T20:47:02"
lang: "ar"
translationKey: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
slug: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
author: "NewsBot (Validated by Federico Sella)"
description: "عضو في عصابة أkira للفدية يعطل أنظمة كشف الاستجابة الطرفية عن طريق الإقلاع في الوضع الآمن مع الشبكات، ويسرق البيانات لكنه يفشل في التشفير. تعلم كيفية الدفاع."
original_url: "https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/"
source: "BleepingComputer"
severity: "High"
target: "حلول كشف الاستجابة الطرفية (EDR)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

عضو في عصابة أkira للفدية يعطل أنظمة كشف الاستجابة الطرفية عن طريق الإقلاع في الوضع الآمن مع الشبكات، ويسرق البيانات لكنه يفشل في التشفير. تعلم كيفية الدفاع.

{{< cyber-report severity="High" source="BleepingComputer" target="حلول كشف الاستجابة الطرفية (EDR)" >}}

لوحظ أن أحد أعضاء عصابة أkira للفدية يقوم بتعطيل حلول كشف الاستجابة الطرفية (EDR) على الأنظمة المخترقة عن طريق إعادة تشغيل الجهاز في الوضع الآمن مع الشبكات. تسمح هذه التقنية للمهاجم بالعمل دون مراقبة EDR، حيث أن العديد من أدوات الأمان لا يتم تحميلها في الوضع الآمن.

{{< ad-banner >}}

نجح العضو في سرقة بيانات حساسة من شبكة الضحية، لكن مرحلة التشفير في الهجوم فشلت. يشير هذا إلى أنه على الرغم من فعالية تجاوز EDR، إلا أن ضوابط أمنية أخرى أو مشكلات تشغيلية منعت تحميل الحمولة النهائية للفدية من التنفيذ بشكل صحيح.

تسلط هذه الحادثة الضوء على أهمية تعزيز تكوينات الإقلاع ومراقبة عمليات إعادة التشغيل غير المتوقعة، خاصة إلى الوضع الآمن. يجب على المؤسسات أيضًا التأكد من تفعيل الحماية من العبث في حلول EDR وتقييد أو مراقبة الإقلاع في الوضع الآمن.

{{< netrunner-insight >}}

لمحللي SOC، هذا تذكير بأن تجاوز EDR يمكن أن يكون ببساطة إعادة تشغيل إلى الوضع الآمن. راقب أحداث إيقاف التشغيل/إعادة التشغيل غير المعتادة وفكر في تعطيل الإقلاع في الوضع الآمن عبر كلمات مرور BIOS/UEFI أو سياسات المجموعة. يجب على DevSecOps التأكد من تكوين عوامل EDR لبدء التشغيل في الوضع الآمن وتفعيل الحماية من العبث لمنع هذه التقنية الشائعة للمراوغة.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على BleepingComputer ›](https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/)**
