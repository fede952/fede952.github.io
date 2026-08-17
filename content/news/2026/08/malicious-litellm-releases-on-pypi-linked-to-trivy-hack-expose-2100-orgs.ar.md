---
title: "إصدارات LiteLLM الخبيثة على PyPI المرتبطة باختراق Trivy تعرض أكثر من 2100 منظمة للخطر"
date: "2026-08-17T07:48:06Z"
original_date: "2026-08-12T08:04:52"
lang: "ar"
translationKey: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
slug: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
author: "NewsBot (Validated by Federico Sella)"
description: "سرقت حزمتا LiteLLM الخبيثتان على PyPI مفاتيح السحابة ومفاتيح SSH والمزيد. تشير بيانات CloudSEK إلى أن أكثر من 2100 منظمة قد تكون معرضة للخطر."
original_url: "https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html"
source: "The Hacker News"
severity: "High"
target: "مستخدمو LiteLLM على PyPI"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

سرقت حزمتا LiteLLM الخبيثتان على PyPI مفاتيح السحابة ومفاتيح SSH والمزيد. تشير بيانات CloudSEK إلى أن أكثر من 2100 منظمة قد تكون معرضة للخطر.

{{< cyber-report severity="High" source="The Hacker News" target="مستخدمو LiteLLM على PyPI" >}}

تم نشر إصدارين خبيثين من LiteLLM على PyPI وظلا متاحين لمدة 40 دقيقة تقريبًا في مارس. احتوت هذه الحزم على تعليمات برمجية لسرقة بيانات الاعتماد مصممة لجمع مجموعة واسعة من الأسرار، بما في ذلك مفاتيح الوصول إلى السحابة ومفاتيح SSH الخاصة ورموز Kubernetes وكلمات مرور قواعد البيانات من أي نظام يقوم بتثبيتها.

{{< ad-banner >}}

حصلت شركة الاستخبارات التهديدية CloudSEK على مجموعة بيانات مبنية من حوالي 434000 ملف التقطها المهاجمون. يشير تحليل هذه المجموعة إلى أن التعرض قد يؤثر على أكثر من 2100 منظمة، مما يسلط الضوء على الحجم المحتمل للاختراق.

يرتبط الحادث باختراق Trivy السابق، مما يشير إلى هجوم سلسلة توريد منسق. يجب على المؤسسات التي قامت بتثبيت LiteLLM من PyPI خلال الفترة المتأثرة تدوير جميع بيانات الاعتماد المكشوفة على الفور والتحقيق في علامات الوصول غير المصرح به.

{{< netrunner-insight >}}

يؤكد هذا الحادث على الحاجة الماسة لليقظة في سلسلة توريد البرمجيات. يجب على محللي SOC مراقبة أي تثبيتات للإصدارات الخبيثة من LiteLLM وإعطاء الأولوية لتدوير بيانات الاعتماد لأي أسرار قد تكون مكشوفة. يجب على فرق DevSecOps فرض فحوصات صارمة لتكامل الحزم والنظر في استخدام مرايا خاصة أو ملفات قفل مع تجزئات للتخفيف من هذه المخاطر.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html)**
