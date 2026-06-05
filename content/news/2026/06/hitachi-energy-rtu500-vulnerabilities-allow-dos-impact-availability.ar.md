---
title: "ثغرات في أجهزة Hitachi Energy RTU500 تسمح بهجمات حجب الخدمة وتؤثر على التوفر"
date: "2026-06-05T10:46:09Z"
original_date: "2026-06-04T12:00:00"
lang: "ar"
translationKey: "hitachi-energy-rtu500-vulnerabilities-allow-dos-impact-availability"
author: "NewsBot (Validated by Federico Sella)"
description: "تحذر CISA من ثغرات متعددة في سلسلة أجهزة Hitachi Energy RTU500، بما في ذلك إلغاء مرجع مؤشر فارغ وحلقة لا نهائية، بدرجة CVSS 7.8. تم سرد الإصدارات المتأثرة."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04"
source: "CISA"
severity: "High"
target: "البرامج الثابتة لوحدة CMU من سلسلة أجهزة Hitachi Energy RTU500"
cve: "CVE-2025-69421"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تحذر CISA من ثغرات متعددة في سلسلة أجهزة Hitachi Energy RTU500، بما في ذلك إلغاء مرجع مؤشر فارغ وحلقة لا نهائية، بدرجة CVSS 7.8. تم سرد الإصدارات المتأثرة.

{{< cyber-report severity="High" source="CISA" target="البرامج الثابتة لوحدة CMU من سلسلة أجهزة Hitachi Energy RTU500" cve="CVE-2025-69421" cvss="7.8" >}}

كشفت شركة Hitachi Energy عن ثغرات متعددة تؤثر على البرامج الثابتة لوحدة CMU من سلسلة أجهزة RTU500. تشمل العيوب إلغاء مرجع مؤشر فارغ، تجاوز سعة العدد الصحيح أو الالتفاف، وحلقة بشرط خروج غير قابل للوصول (حلقة لا نهائية)، مما قد يؤدي إلى حالات حجب الخدمة. يؤثر الاستغلال بشكل أساسي على توفر المنتج، مع تأثيرات ثانوية محتملة على السرية والتكامل.

{{< ad-banner >}}

النشرة الاستشارية التي نشرتها CISA (ICSA-26-155-04) تسرد إصدارات البرامج الثابتة المتأثرة التي تتراوح من 12.7.1 إلى 13.8.1. ترتبط عدة CVEs، بما في ذلك CVE-2025-69421 وCVE-2026-24515 وCVE-2026-25210 وCVE-2026-32776 وCVE-2026-32777 وCVE-2026-32778 وCVE-2026-8479. تبلغ درجة الأساس CVSS v3 للثغرات 7.8، مما يشير إلى خطورة عالية.

توصي شركة Hitachi Energy باتخاذ إجراء فوري وفقًا لإرشادات المعالجة في النشرة الاستشارية. نظرًا لسياق البنية التحتية الحيوية، يجب على المؤسسات التي تستخدم إصدارات RTU500 المتأثرة إعطاء الأولوية للتصحيح وتنفيذ تجزئة الشبكة للتخفيف من مخاطر الاستغلال.

{{< netrunner-insight >}}

تذكرنا هذه الثغرات بأن أجهزة OT غالبًا ما تتأخر في دورات التصحيح. يجب على فرق SOC مراقبة حركة المرور غير الطبيعية لوحدات RTU500 وضمان عزل هذه الأجهزة عن الشبكات غير الموثوقة. يجب على مهندسي DevSecOps دمج فحص البرامج الثابتة في خطوط أنابيب CI/CD لاكتشاف CVEs المعروفة قبل النشر.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04)**
