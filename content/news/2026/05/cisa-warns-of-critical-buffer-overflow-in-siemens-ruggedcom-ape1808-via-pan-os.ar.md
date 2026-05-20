---
title: "CISA تحذر من تجاوز سعة المخزن المؤقت الحرج في أجهزة Siemens RUGGEDCOM APE1808 عبر PAN-OS"
date: "2026-05-20T10:21:56Z"
original_date: "2026-05-19T12:00:00"
lang: "ar"
translationKey: "cisa-warns-of-critical-buffer-overflow-in-siemens-ruggedcom-ape1808-via-pan-os"
author: "NewsBot (Validated by Federico Sella)"
description: "يؤثر تجاوز سعة المخزن المؤقت في بوابة Captive Portal الخاصة بـ Palo Alto Networks PAN-OS على أجهزة Siemens RUGGEDCOM APE1808. يسمح CVE-2026-0300 بتنفيذ تعليمات برمجية عن بعد بدون مصادقة بصلاحيات الجذر."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02"
source: "CISA"
severity: "Critical"
target: "أجهزة Siemens RUGGEDCOM APE1808"
cve: "CVE-2026-0300"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

يؤثر تجاوز سعة المخزن المؤقت في بوابة Captive Portal الخاصة بـ Palo Alto Networks PAN-OS على أجهزة Siemens RUGGEDCOM APE1808. يسمح CVE-2026-0300 بتنفيذ تعليمات برمجية عن بعد بدون مصادقة بصلاحيات الجذر.

{{< cyber-report severity="Critical" source="CISA" target="أجهزة Siemens RUGGEDCOM APE1808" cve="CVE-2026-0300" cvss="10.0" >}}

نشرت CISA نشرة استشارية (ICSA-26-139-02) تفصل ثغرة تجاوز سعة المخزن المؤقت الحرجة في خدمة بوابة مصادقة المستخدم (Captive Portal) لبرنامج Palo Alto Networks PAN-OS. هذا الخلل، الذي تم تتبعه باسم CVE-2026-0300 ودرجة CVSS 10.0، يسمح لمهاجم غير مصادق بتنفيذ تعليمات برمجية عشوائية بصلاحيات الجذر على جدران الحماية من سلسلة PA وVM عن طريق إرسال حزم مصممة خصيصًا.

{{< ad-banner >}}

تؤثر الثغرة على أجهزة Siemens RUGGEDCOM APE1808 بجميع الإصدارات. تستعد Siemens لإصدار إصدارات التصحيح وتوصي بتنفيذ الحلول البديلة المقدمة في إشعارات الأمان الصادرة عن Palo Alto Networks. إلى أن تتوفر التصحيحات، يجب على المؤسسات تعطيل خدمة Captive Portal إذا لم تكن مطلوبة وتقييد الوصول إلى الشبكة للأجهزة المتأثرة.

نظرًا لدرجة CVSS الحرجة واحتمالية الاختراق الكامل للنظام، فإن الإجراء الفوري مبرر. تستهدف النشرة الاستشارية قطاع التصنيع الحرج، مع نشر الأجهزة في جميع أنحاء العالم. يجب على المشغلين إعطاء الأولوية لتطبيق التخفيفات ومراقبة أي علامات استغلال.

{{< netrunner-insight >}}

هذا مثال نموذجي لمخاطر سلسلة التوريد: مكون طرف ثالث (PAN-OS) يقدم ثغرة حرجة في منتج صناعي. يجب على محللي SOC البحث فورًا عن حركة مرور غير طبيعية إلى منافذ Captive Portal وضمان أن التقسيم يحد من التعرض. يجب على فرق DevSecOps جرد جميع حالات RUGGEDCOM APE1808 وتطبيق التخفيفات الصادرة عن Palo Alto Networks دون تأخير.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02)**
