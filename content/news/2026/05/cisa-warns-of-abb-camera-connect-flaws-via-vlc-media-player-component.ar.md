---
title: "CISA تحذر من ثغرات في ABB Camera Connect عبر مكون VLC Media Player"
date: "2026-05-27T10:51:57Z"
original_date: "2026-05-26T12:00:00"
lang: "ar"
translationKey: "cisa-warns-of-abb-camera-connect-flaws-via-vlc-media-player-component"
author: "NewsBot (Validated by Federico Sella)"
description: "إصدارات ABB Ability Camera Connect ≤1.5.0.14 تتضمن مشغل VLC media player 2.2.4 ضعيفًا مع العديد من أخطاء تلف الذاكرة، بما في ذلك CVE-2024-46461، مما يشكل خطرًا حرجًا."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05"
source: "CISA"
severity: "Critical"
target: "ABB Ability Camera Connect"
cve: "CVE-2024-46461"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

إصدارات ABB Ability Camera Connect ≤1.5.0.14 تتضمن مشغل VLC media player 2.2.4 ضعيفًا مع العديد من أخطاء تلف الذاكرة، بما في ذلك CVE-2024-46461، مما يشكل خطرًا حرجًا.

{{< cyber-report severity="Critical" source="CISA" target="ABB Ability Camera Connect" cve="CVE-2024-46461" cvss="9.8" >}}

أصدرت CISA نشرة استشارية (ICSA-26-146-05) تفصل العديد من الثغرات في إصدارات ABB Ability Camera Connect 1.5.0.14 وما دونها. تنشأ الثغرات من مكون طرف ثالث قديم، وهو مشغل VLC media player الإصدار 2.2.4، المضمن مع حزمة التثبيت. يعمل التحديث إلى الإصدار 1.5.0.15 على حل المشكلة عن طريق استبدال المكون الضعيف.

{{< ad-banner >}}

تشمل الثغرات تجاوز سعة المخزن المؤقت في الكومة، وتدفق عدد صحيح سفلي، وكتابة خارج الحدود، وعنصر مسار بحث غير متحكم فيه، وفيضان عدد صحيح، وخطأ خارج بواحد، وقراءة خارج الحدود، وتحرير مزدوج، وتقييد غير صحيح للعمليات داخل مخازن الذاكرة، واستخدام بعد التحرير. على وجه الخصوص، يصف CVE-2024-46461 تجاوز سعة في الكومة في مشغل VLC media player 3.0.20 والإصدارات الأقدم عبر تدفق MMS تم إنشاؤه بشكل ضار، مما يؤدي إلى رفض الخدمة.

مع درجة CVSS v3 تبلغ 9.8، تم تصنيف هذه الثغرات على أنها حرجة. تشمل قطاعات البنية التحتية الحيوية المتأثرة الكيميائية والمرافق التجارية والاتصالات والتصنيع الحيوي والطاقة وأنظمة النقل. يتم نشر المنتج في جميع أنحاء العالم، ويمكن أن يسمح الاستغلال للمهاجم باختراق النظام بطرق مختلفة.

{{< netrunner-insight >}}

تؤكد هذه النشرة الاستشارية على خطر الثغرات الموروثة من مكونات الطرف الثالث. يجب على محللي SOC إعطاء الأولوية لتصحيح ABB Ability Camera Connect إلى الإصدار 1.5.0.15 ومراقبة محاولات الاستغلال التي تستهدف ثغرات مشغل VLC media player. يجب على فرق DevSecOps فرض التحكم الصارم في إصدارات المكونات والفحص المنتظم للمكتبات المضمنة.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05)**
