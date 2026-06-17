---
title: "CISA تحذر من ثغرة في Rockwell RSLinx Classic تؤدي إلى رفض الخدمة"
date: "2026-06-17T11:42:55Z"
original_date: "2026-06-16T12:00:00"
lang: "ar"
translationKey: "cisa-warns-of-rockwell-rslinx-classic-flaw-leading-to-dos"
author: "NewsBot (Validated by Federico Sella)"
description: "تحذير CISA يسلط الضوء على CVE-2020-13573، وهي ثغرة تجاوز سعة المخزن المؤقت في Rockwell Automation RSLinx Classic الإصدار 4.50.00 وما دونه، مما يعرض لخطر رفض الخدمة وتنفيذ التعليمات البرمجية عن بُعد."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02"
source: "CISA"
severity: "High"
target: "Rockwell Automation RSLinx Classic"
cve: "CVE-2020-13573"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تحذير CISA يسلط الضوء على CVE-2020-13573، وهي ثغرة تجاوز سعة المخزن المؤقت في Rockwell Automation RSLinx Classic الإصدار 4.50.00 وما دونه، مما يعرض لخطر رفض الخدمة وتنفيذ التعليمات البرمجية عن بُعد.

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation RSLinx Classic" cve="CVE-2020-13573" cvss="7.5" >}}

أصدرت CISA تحذيرًا (ICSA-26-167-02) بشأن ثغرة أمنية في Rockwell Automation RSLinx Classic، وهو برنامج اتصالات صناعي واسع الاستخدام. الثغرة، المعروفة باسم CVE-2020-13573، هي تجاوز سعة المخزن المؤقت في المكدس يمكن استغلالها عن بُعد لتنفيذ تعليمات برمجية عشوائية أو التسبب في رفض الخدمة، مما يترك التطبيق غير مستجيب وغير قادر على التعافي تلقائيًا.

{{< ad-banner >}}

الإصدارات المتأثرة تشمل RSLinx Classic حتى الإصدار 4.50.00. تحمل الثغرة درجة CVSS v3 تبلغ 7.5، مما يشير إلى خطورة عالية. توصي Rockwell Automation بالترقية إلى الإصدار 4.60.00 أو أحدث، أو تطبيق التصحيح BF31213 للعملاء غير القادرين على الترقية فورًا. يشير التحذير أيضًا إلى CWE-125 (قراءة خارج الحدود) كضعف أساسي.

نظرًا لقطاعات البنية التحتية الحيوية المعنية—التصنيع الحيوي، الطاقة، الغذاء والزراعة، والمياه والصرف الصحي—والانتشار العالمي للمنتج، فإن التصحيح في الوقت المناسب ضروري. يجب على المؤسسات إعطاء الأولوية لهذا التحديث للتخفيف من خطر الاستغلال، خاصة في البيئات التي يكون فيها RSLinx Classic مكشوفًا لشبكات غير موثوقة.

{{< netrunner-insight >}}

بالنسبة لمحللي SOC، راقبوا الأعطال غير المعتادة أو عدم الاستجابة في عمليات RSLinx Classic، حيث قد تشير إلى محاولات استغلال. يجب على فرق DevSecOps التخطيط فورًا للترقية إلى الإصدار 4.60.00 أو تطبيق التصحيح BF31213، والتأكد من أن مثيلات RSLinx غير قابلة للوصول مباشرة من الإنترنت. نظرًا لدرجة CVSS وإمكانية تنفيذ التعليمات البرمجية عن بُعد، تعامل مع هذا كعنصر علاج ذي أولوية عالية.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02)**
