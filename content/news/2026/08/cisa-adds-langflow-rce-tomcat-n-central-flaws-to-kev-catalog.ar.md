---
title: "CISA يضيف ثغرات Langflow RCE وTomcat وN-central إلى كتالوج KEV"
date: "2026-08-05T09:30:51Z"
original_date: "2026-08-05T07:40:39"
lang: "ar"
translationKey: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
slug: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA تشير إلى ثلاث ثغرات تم استغلالها بنشاط بما في ذلك Langflow RCE (CVE-2026-9198) بتقييم CVSS 9.8، وتحث على التصحيح الفوري."
original_url: "https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html"
source: "The Hacker News"
severity: "Critical"
target: "Langflow, Apache Tomcat, N-central"
cve: "CVE-2026-9198"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA تشير إلى ثلاث ثغرات تم استغلالها بنشاط بما في ذلك Langflow RCE (CVE-2026-9198) بتقييم CVSS 9.8، وتحث على التصحيح الفوري.

{{< cyber-report severity="Critical" source="The Hacker News" target="Langflow, Apache Tomcat, N-central" cve="CVE-2026-9198" cvss="9.8" kev="true" >}}

أضافت وكالة الأمن السيبراني وأمن البنية التحتية الأمريكية (CISA) ثلاث ثغرات إلى كتالوج الثغرات المعروفة المستغلة (KEV)، مستشهدة بأدلة على استغلال نشط. ومن بينها CVE-2026-9198، وهي ثغرة حقن كود حرجة في Langflow تسمح للمهاجمين غير المصادق عليهم بتحقيق تنفيذ كود عن بعد كامل. تحمل الثغرة تقييم CVSS قدره 9.8، مما يشير إلى خطر شديد.

{{< ad-banner >}}

تؤثر الثغرتان الأخريان على Apache Tomcat وN-central، على الرغم من عدم تقديم تفاصيل محددة في الملخص. كتالوج KEV الخاص بـ CISA هو قائمة ذات أولوية من الثغرات المعروفة باستغلالها، ويتعين على الوكالات الفيدرالية معالجتها ضمن جداول زمنية محددة. تحث المنظمات على مراجعة الكتالوج وتطبيق التصحيحات فورًا.

يؤكد إدراج هذه الثغرات على أهمية إدارة التصحيح في الوقت المناسب واستخبارات التهديدات. يجب على فرق الأمن مراقبة مؤشرات الاختراق المتعلقة بهذه الـ CVEs والتأكد من أن أصولهم غير معرضة لنواقل الهجوم المعروفة.

{{< netrunner-insight >}}

لمحللي SOC، أعطوا الأولوية لمراقبة محاولات الاستغلال ضد Langflow وTomcat وN-central، حيث أصبحت هذه الآن أهدافًا نشطة مؤكدة. يجب على DevSecOps تسريع التصحيح، خاصة للنسخ المتصلة بالإنترنت، والنظر في تنفيذ قواعد كشف إضافية لنشاط ما بعد الاستغلال. نظرًا لتقييم CVSS الحرج، تعامل مع CVE-2026-9198 كخطر من الدرجة الأولى وتحقق من عدم حدوث وصول غير مصرح به.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html)**
