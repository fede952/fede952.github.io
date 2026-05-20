---
title: "ثغرة في كاميرات ZKTeco CCTV تكشف بيانات الاعتماد عبر منفذ غير موثق"
date: "2026-05-20T10:24:09Z"
original_date: "2026-05-19T12:00:00"
lang: "ar"
translationKey: "zkteco-cctv-cameras-flaw-exposes-credentials-via-unauthenticated-port"
author: "NewsBot (Validated by Federico Sella)"
description: "تحذر CISA من ثغرة CVE-2026-8598 في كاميرات ZKTeco CCTV، والتي تسمح بسرقة بيانات الاعتماد عبر منفذ غير موثق. التصحيح متاح في البرنامج الثابت V5.0.1.2.20260421."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04"
source: "CISA"
severity: "Critical"
target: "كاميرات ZKTeco CCTV"
cve: "CVE-2026-8598"
cvss: 9.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تحذر CISA من ثغرة CVE-2026-8598 في كاميرات ZKTeco CCTV، والتي تسمح بسرقة بيانات الاعتماد عبر منفذ غير موثق. التصحيح متاح في البرنامج الثابت V5.0.1.2.20260421.

{{< cyber-report severity="Critical" source="CISA" target="كاميرات ZKTeco CCTV" cve="CVE-2026-8598" cvss="9.1" >}}

نشرت CISA نشرة استشارية (ICSA-26-139-04) تفصل ثغرة خطيرة في تجاوز المصادقة في كاميرات ZKTeco CCTV. الثغرة، المسجلة باسم CVE-2026-8598، تتعلق بمنفذ تصدير تهيئة غير موثق يمكن الوصول إليه دون مصادقة. قد يؤدي الاستغلال الناجح إلى كشف المعلومات، بما في ذلك التقاط بيانات اعتماد حساب الكاميرا.

{{< ad-banner >}}

تؤثر الثغرة على إصدارات البرامج الثابتة لـ ZKTeco SSC335-GC2063-Face-0b77 Solution قبل V5.0.1.2.20260421. درجة CVSS v3 الأساسية هي 9.1، مما يشير إلى خطورة حرجة. الأجهزة المتضررة منتشرة عالميًا عبر المرافق التجارية، ويقع مقر البائع في الصين.

أصدرت ZKTeco إصدارًا مصححًا من البرنامج الثابت V5.0.1.2.20260421 لمعالجة المشكلة. يُنصح المستخدمون بشدة بالترقية فورًا. تُصنف الثغرة ضمن CWE-288 (تجاوز المصادقة باستخدام مسار أو قناة بديلة).

{{< netrunner-insight >}}

هذا مثال نموذجي لواجهة تصحيح مكشوفة تتحول إلى باب خلفي. يجب على محللي SOC فحص شبكتهم فورًا بحثًا عن كاميرات ZKTeco والتحقق من إصدارات البرامج الثابتة. بالنسبة لـ DevSecOps، يؤكد هذا على ضرورة تعطيل أو جدارنة المنافذ غير الموثقة في بناءات البرامج الثابتة لإنترنت الأشياء. تعامل مع أي كاميرا بإصدار برنامج ثابت أقل من V5.0.1.2.20260421 على أنها مخترقة حتى يثبت العكس.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04)**
