---
title: "ثغرات في ABB B&R Automation Studio تعرض أنظمة التحكم الصناعي لتنفيذ تعليمات برمجية عن بُعد"
date: "2026-05-23T09:00:47Z"
original_date: "2026-05-21T12:00:00"
lang: "ar"
translationKey: "abb-b-r-automation-studio-flaws-expose-ics-to-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "تحذر CISA من 25 ثغرة في ABB B&R Automation Studio، بما في ذلك ثغرات حرجة بتقييم CVSS 9.8 قد تمكن من الوصول غير المصرح به وتنفيذ تعليمات برمجية عن بُعد."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03"
source: "CISA"
severity: "Critical"
target: "ABB B&R Automation Studio"
cve: "CVE-2025-6965"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تحذر CISA من 25 ثغرة في ABB B&R Automation Studio، بما في ذلك ثغرات حرجة بتقييم CVSS 9.8 قد تمكن من الوصول غير المصرح به وتنفيذ تعليمات برمجية عن بُعد.

{{< cyber-report severity="Critical" source="CISA" target="ABB B&R Automation Studio" cve="CVE-2025-6965" cvss="9.8" >}}

نشرت CISA نشرة استشارية تفصّل ثغرات متعددة في ABB B&R Automation Studio، تؤثر على الإصدارات الأقدم من 6.5 والإصدار 6.5. تسرد النشرة 25 CVE، بما في ذلك CVE-2025-6965 وCVE-2025-3277 وCVE-2023-7104 وغيرها. تنشأ هذه الثغرات من مكونات طرف ثالث قديمة وتتضمن مشكلات مثل تجاوز سعة المخزن المؤقت المستند إلى الكومة، وكتابة خارج الحدود، واستخدام بعد التحرير، والتحقق غير السليم من الإدخال.

{{< ad-banner >}}

على الرغم من أن ABB لم تبلغ عن أي استغلال ملاحظ أثناء الاختبار، إلا أن الثغرات قد تشكل نواقل هجوم للوصول غير المصرح به، أو كشف البيانات، أو تنفيذ تعليمات برمجية عن بُعد. تحمل أكثر CVEs خطورة درجة CVSS v3 تبلغ 9.8، مما يشير إلى خطورة حرجة. تُستخدم المنتجات المتأثرة في أنظمة الأتمتة الصناعية والتحكم، مما يجعلها أهدافًا جذابة للجهات الخبيثة.

أصدرت ABB تحديثًا يستبدل مكون الطرف الثالث القديم. يُحث المؤسسات التي تستخدم B&R Automation Studio على تطبيق التحديث فورًا. نظرًا للطبيعة الحرجة لهذه الثغرات وإمكانية الاستغلال عن بُعد، يجب على مالكي الأصول إعطاء الأولوية للتصحيح ومراقبة أي علامات على الاختراق.

{{< netrunner-insight >}}

لمحللي SOC ومهندسي DevSecOps، تؤكد هذه النشرة على مخاطر تبعيات الطرف الثالث في برامج ICS. العدد الكبير من CVEs (25) يشير إلى مشكلة نظامية في إدارة المكونات. أعطِ الأولوية لجرد مثيلات B&R Automation Studio وقم بتطبيق تحديث البائع. بالإضافة إلى ذلك، قم بتقسيم شبكات ICS للحد من التعرض وتنفيذ مراقبة للسلوك الشاذ الذي قد يشير إلى محاولات استغلال.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03)**
