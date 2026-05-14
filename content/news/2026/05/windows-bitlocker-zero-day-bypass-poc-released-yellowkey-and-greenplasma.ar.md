---
title: "إصدار إثبات المفهوم لتجاوز ثغرة BitLocker في Windows: YellowKey وGreenPlasma"
date: "2026-05-14T09:30:15Z"
original_date: "2026-05-13T16:37:49"
lang: "ar"
translationKey: "windows-bitlocker-zero-day-bypass-poc-released-yellowkey-and-greenplasma"
author: "NewsBot (Validated by Federico Sella)"
description: "تم نشر إثباتات المفهوم لاستغلال ثغرتين غير مصححتين في Windows—YellowKey (تجاوز BitLocker) وGreenPlasma (تصعيد الامتيازات)—مما يشكل مخاطر على الأقراص المشفرة."
original_url: "https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/"
source: "BleepingComputer"
severity: "High"
target: "أقراص Windows المحمية بواسطة BitLocker"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تم نشر إثباتات المفهوم لاستغلال ثغرتين غير مصححتين في Windows—YellowKey (تجاوز BitLocker) وGreenPlasma (تصعيد الامتيازات)—مما يشكل مخاطر على الأقراص المشفرة.

{{< cyber-report severity="High" source="BleepingComputer" target="أقراص Windows المحمية بواسطة BitLocker" >}}

قام باحث في الأمن السيبراني بنشر إثباتات المفهوم (PoC) لاستغلال ثغرتين غير مصححتين في Microsoft Windows، تُعرفان باسم YellowKey وGreenPlasma. YellowKey هو تجاوز لـ BitLocker يسمح للمهاجمين بالوصول إلى البيانات على الأقراص المحمية دون مصادقة مناسبة، بينما GreenPlasma هو ثغرة تصعيد امتيازات يمكن أن تمكن المهاجم من الحصول على صلاحيات مرتفعة على نظام مخترق.

{{< ad-banner >}}

يزيد نشر إثباتات المفهوم هذه من خطر الاستغلال، حيث يمكن للجهات الخبيثة الآن تحويل التقنيات إلى أسلحة. يجب على المؤسسات التي تعتمد على BitLocker لتشفير القرص بالكامل تقييم تعرضها والنظر في ضوابط أمنية إضافية، مثل تفعيل حماية TPM+PIN أو استخدام المصادقة قبل الإقلاع.

لم تصدر Microsoft بعد تصحيحات لهذه الثغرات، مما يترك الأنظمة مكشوفة حتى يتم نشر الإصلاحات. يجب على فرق الأمن مراقبة أنماط الوصول غير المعتادة إلى الأقراص المشفرة وتطبيق الحلول البديلة حيثما أمكن، مثل تعطيل خيارات الإقلاع غير الضرورية أو فرض سياسات PIN قوية.

{{< netrunner-insight >}}

لمحللي SOC، أعط الأولوية لمراقبة محاولات الوصول غير المصرح بها إلى أقراص BitLocker المحمية وأحداث تصعيد الامتيازات. يجب على مهندسي DevSecOps اختبار بيئاتهم ضد إثباتات المفهوم المنشورة لتحديد التكوينات الضعيفة وتنفيذ ضوابط تعويضية مثل Secure Boot وسجلات الإقلاع المقاسة.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على BleepingComputer ›](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)**
