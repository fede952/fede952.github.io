---
title: "حملة تسجيل مفتاح Entra وهمي تستهدف مستخدمي Microsoft 365 في هجوم ابتزاز بيانات"
date: "2026-07-12T09:00:42Z"
original_date: "2026-07-10T10:30:20"
lang: "ar"
translationKey: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
slug: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "يستخدم الجهات الفاعلة O-UNC-066 التصيد الصوتي لخداع المستخدمين لتسجيل مفتاح Entra وهمي، بهدف اختراق حسابات Microsoft 365 لابتزاز البيانات."
original_url: "https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html"
source: "The Hacker News"
severity: "High"
target: "مستخدمو Microsoft 365"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

يستخدم الجهات الفاعلة O-UNC-066 التصيد الصوتي لخداع المستخدمين لتسجيل مفتاح Entra وهمي، بهدف اختراق حسابات Microsoft 365 لابتزاز البيانات.

{{< cyber-report severity="High" source="The Hacker News" target="مستخدمو Microsoft 365" >}}

تم رصد جهة تهديد تُعرف باسم O-UNC-066 من قبل Okta وهي تشن هجمات تصيد صوتي تستهدف مستخدمي Microsoft 365 في قطاعات متعددة. ينتحل المهاجمون صفة طلبات أمنية مشروعة لخداع الضحايا لتسجيل مفتاح Entra وهمي، مما يمنح الخصم وصولاً غير مصرح به إلى حساباتهم.

{{< ad-banner >}}

تستخدم الحملة مجموعة أدوات تصيد يتم التحكم فيها عبر لوحة تحكم مصممة خصيصًا لاعتراض عملية تسجيل المفتاح. بمجرد حصول المهاجم على الوصول، يهدف إلى تنفيذ ابتزاز البيانات، وسرقة المعلومات الحساسة والمطالبة بفدية. تسلط الهجمات الضوء على اتجاه متزايد لاستخدام القنوات الصوتية لتجاوز دفاعات التصيد التقليدية القائمة على البريد الإلكتروني.

يُنصح المؤسسات بتطبيق المصادقة متعددة العوامل (MFA) باستخدام مفاتيح أمان مادية وتوعية المستخدمين بالتحقق من أي طلبات أمنية غير مرغوب فيها عبر قنوات اتصال بديلة. يمكن أن تساعد مراقبة أنشطة تسجيل المفاتيح غير المعتادة في اكتشاف مثل هذه الهجمات مبكرًا.

{{< netrunner-insight >}}

يؤكد هذا الهجوم على أهمية التعامل مع الطلبات الأمنية الصوتية بنفس الشكوك التي تتعامل بها مع رسائل التصيد الإلكتروني. يجب على محللي SOC مراقبة محاولات تسجيل المفاتيح غير المعتادة والتأكد من أن عمليات تسجيل MFA تتطلب تحققًا خارج النطاق. يجب على فرق DevSecOps النظر في تنفيذ سياسات وصول شرطية تقيد تسجيل المفاتيح بالأجهزة والمواقع الموثوقة.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html)**
