---
title: "ثغرة غير مصححة في معالج URI للبحث في Windows تسرب تجزئات NTLMv2"
date: "2026-06-03T11:53:18Z"
original_date: "2026-06-03T10:18:52"
lang: "ar"
translationKey: "unpatched-windows-search-uri-flaw-leaks-ntlmv2-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "يكشف باحثون عن ثغرة أمنية غير مصححة في معالج URI للبحث في Windows يمكنها كشف تجزئات NTLMv2، على غرار ثغرة CVE-2026-33829 في أداة القصاصات."
original_url: "https://thehackernews.com/2026/06/unpatched-windows-search-uri.html"
source: "The Hacker News"
severity: "High"
target: "معالج URI للبحث في Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

يكشف باحثون عن ثغرة أمنية غير مصححة في معالج URI للبحث في Windows يمكنها كشف تجزئات NTLMv2، على غرار ثغرة CVE-2026-33829 في أداة القصاصات.

{{< cyber-report severity="High" source="The Hacker News" target="معالج URI للبحث في Windows" >}}

كشف باحثو الأمن السيبراني في Huntress عن تفاصيل ثغرة أمنية غير مصححة في معالج URI للبحث في Windows يمكن أن تسمح للمهاجمين بسرقة تجزئات NTLMv2. تشبه المشكلة ثغرة CVE-2026-33829، وهي ثغرة تزوير في معالج URI ms-screensketch لأداة القصاصات في Windows والتي كشفت أيضًا تجزئات NTLM.

{{< ad-banner >}}

تقع الثغرة المكتشفة حديثًا في مخطط URI للبحث، والذي يُستخدم لتشغيل استعلامات بحث Windows. من خلال إنشاء رابط أو ملف ضار يؤدي إلى تشغيل معالج URI للبحث، يمكن للمهاجم إجبار النظام المستهدف على المصادقة على خادم بعيد، مما يؤدي إلى تسريب تجزئة NTLMv2 للمستخدم. يمكن بعد ذلك كسر هذه التجزئة دون اتصال بالإنترنت أو استخدامها في هجمات الترحيل.

حتى تاريخ النشر، لم يتم إصدار أي تصحيح رسمي من Microsoft. يُنصح المؤسسات بمراقبة التحديثات والنظر في حظر معالج URI للبحث عبر نهج المجموعة أو أدوات أمان نقطة النهاية حتى يتوفر إصلاح.

{{< netrunner-insight >}}

هذا ناقل ترحيل NTLM كلاسيكي يجب على محللي SOC مراقبته في سجلات المصادقة. يجب على مهندسي DevSecOps مراجعة أي استخدام لمعالجات URI في بيئاتهم فورًا والنظر في تطبيق إجراءات تخفيف مثل تعطيل NTLMv2 أو فرض توقيع SMB. حتى تقوم Microsoft بتصحيح ذلك، افترض أن URI للبحث هو نقطة دخول محتملة لسرقة بيانات الاعتماد.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/06/unpatched-windows-search-uri.html)**
