---
title: "مجموعة UAC-0145 المرتبطة بـ Sandworm تستخدم مقابلات عمل وهمية لنشر VPN خبيث"
date: "2026-08-15T07:23:49Z"
original_date: "2026-08-11T18:36:47"
lang: "ar"
translationKey: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
slug: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
author: "NewsBot (Validated by Federico Sella)"
description: "تحذر CERT-UA من جهات تهديد تابعة لدولة روسية تستهدف عمال تكنولوجيا المعلومات الأوكرانيين عبر مقابلات عمل وهمية، وتقديم VPN يمكنه تنفيذ أوامر."
original_url: "https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html"
source: "The Hacker News"
severity: "High"
target: "عمال تكنولوجيا المعلومات الأوكرانيون"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تحذر CERT-UA من جهات تهديد تابعة لدولة روسية تستهدف عمال تكنولوجيا المعلومات الأوكرانيين عبر مقابلات عمل وهمية، وتقديم VPN يمكنه تنفيذ أوامر.

{{< cyber-report severity="High" source="The Hacker News" target="عمال تكنولوجيا المعلومات الأوكرانيون" >}}

كشفت CERT-UA عن حملة هندسة اجتماعية جديدة تُنسب إلى مجموعة التهديد UAC-0145، وهي مجموعة فرعية من مجموعة الدولة الروسية Sandworm (APT44). تستهدف الحملة عمال تكنولوجيا المعلومات في أوكرانيا من خلال انتحال صفة مسؤولي توظيف وإغراء الضحايا بمقابلات عمل وهمية.

{{< ad-banner >}}

أثناء عملية المقابلة، يتم خداع الضحايا لتثبيت تطبيق VPN هو في الواقع برنامج ضار قادر على تنفيذ أوامر عشوائية على النظام المخترق. تستغل هذه التقنية الثقة المرتبطة بالتوظيف لتجاوز دفاعات المستخدم.

يؤكد هذا النشاط التهديد الإلكتروني المستمر من جهات فاعلة تابعة للدولة الروسية ضد المنظمات الأوكرانية، خاصة في قطاع تكنولوجيا المعلومات. يُبرز إسناد CERT-UA إلى UAC-0145 الطبيعة المتطورة والمستمرة لهذه الهجمات.

{{< netrunner-insight >}}

توضح هذه الحملة فعالية الهندسة الاجتماعية في توصيل البرامج الضارة حتى لمحترفي تكنولوجيا المعلومات المهتمين بالأمن. يجب على محللي SOC تثقيف المستخدمين حول مثل هذه الحيل القائمة على التوظيف ومراقبة عمليات تثبيت VPN غير المعتادة أو تنفيذ الأوامر. يجب على فرق DevSecOps فرض قائمة السماح للتطبيقات وتقييد تنفيذ الملفات الثنائية غير الموقعة للتخفيف من هذه التهديدات.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html)**
