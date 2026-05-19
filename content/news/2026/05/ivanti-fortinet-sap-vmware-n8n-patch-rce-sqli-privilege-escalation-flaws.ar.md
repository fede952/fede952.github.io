---
title: "إيفانتي، فورتينت، SAP، VMware، n8n يصححون ثغرات RCE وSQLi ورفع الامتيازات"
date: "2026-05-19T10:36:29Z"
original_date: "2026-05-18T10:54:05"
lang: "ar"
translationKey: "ivanti-fortinet-sap-vmware-n8n-patch-rce-sqli-privilege-escalation-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "عدة بائعين يصدرون إصلاحات أمنية لثغرات حرجة بما في ذلك Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) التي قد تؤدي إلى كشف معلومات أو هجمات من جانب العميل."
original_url: "https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html"
source: "The Hacker News"
severity: "Critical"
target: "Ivanti Xtraction"
cve: "CVE-2026-8043"
cvss: 9.6
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

عدة بائعين يصدرون إصلاحات أمنية لثغرات حرجة بما في ذلك Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) التي قد تؤدي إلى كشف معلومات أو هجمات من جانب العميل.

{{< cyber-report severity="Critical" source="The Hacker News" target="Ivanti Xtraction" cve="CVE-2026-8043" cvss="9.6" >}}

أصدرت Ivanti وFortinet وn8n وSAP وVMware تصحيحات أمنية تعالج عدة ثغرات يمكن استغلالها لتجاوز المصادقة وتنفيذ تعليمات برمجية عشوائية. الثغرة الأكثر خطورة هي CVE-2026-8043 في Ivanti Xtraction، بدرجة CVSS 9.6، والتي تسمح بالتحكم الخارجي في اسم ملف مما يؤدي إلى كشف معلومات أو هجمات من جانب العميل.

{{< ad-banner >}}

بائعون آخرون عالجوا أيضًا مشكلات عالية الخطورة بما في ذلك ثغرات حقن SQL ورفع الامتيازات. تُحث المؤسسات على إعطاء أولوية لتصحيح هذه الثغرات، خاصة تلك المعرضة للإنترنت، حيث يمكن ربطها لتحقيق اختراق كامل للنظام.

على الرغم من عدم الإبلاغ عن استغلال نشط حتى الآن، فإن سطح الهجوم الواسع ودرجات CVSS العالية تستدعي اهتمامًا فوريًا من فرق الأمن. يعد الفحص المنتظم للثغرات وإدارة التصحيحات أمرًا بالغ الأهمية لتخفيف المخاطر.

{{< netrunner-insight >}}

يجب على محللي SOC إعطاء أولوية لتصحيح Ivanti Xtraction CVE-2026-8043 بسبب درجة CVSS الحرجة وإمكانية الهجمات من جانب العميل. يجب على فرق DevSecOps التحقق من تحديث جميع الأنظمة المتأثرة ومراقبة أي علامات على الاستغلال، حيث يمكن أن يؤدي التحكم الخارجي في أسماء الملفات إلى تسرب البيانات أو الحركة الجانبية.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html)**
