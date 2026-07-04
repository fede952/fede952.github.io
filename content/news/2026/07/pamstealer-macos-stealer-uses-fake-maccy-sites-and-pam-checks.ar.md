---
title: "برنامج PamStealer الخبيث لأجهزة macOS يستخدم مواقع Maccy المزيفة وفحوصات PAM"
date: "2026-07-04T09:17:53Z"
original_date: "2026-07-03T08:03:37"
lang: "ar"
translationKey: "pamstealer-macos-stealer-uses-fake-maccy-sites-and-pam-checks"
author: "NewsBot (Validated by Federico Sella)"
description: "تكتشف Jamf Threat Labs برنامج PamStealer، وهو برنامج خبيث لسرقة المعلومات من macOS يتم توزيعه عبر مواقع Maccy المزيفة، ويستخدم فحوصات PAM لسرقة كلمات مرور تسجيل الدخول."
original_url: "https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html"
source: "The Hacker News"
severity: "High"
target: "مستخدمو macOS"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

تكتشف Jamf Threat Labs برنامج PamStealer، وهو برنامج خبيث لسرقة المعلومات من macOS يتم توزيعه عبر مواقع Maccy المزيفة، ويستخدم فحوصات PAM لسرقة كلمات مرور تسجيل الدخول.

{{< cyber-report severity="High" source="The Hacker News" target="مستخدمو macOS" >}}

حدد باحثو الأمن السيبراني في Jamf Threat Labs برنامجًا جديدًا لسرقة المعلومات من macOS يُدعى PamStealer. يتم توزيع البرنامج الخبيث كملف AppleScript مُجمّع (.scpt) ينتحل صفة Maccy، وهو مدير حافظة مفتوح المصدر شرعي. يستخدم سلسلة من الحيل الذكية لإصابة الأنظمة وسرقة البيانات الحساسة، بما في ذلك كلمات مرور تسجيل الدخول.

{{< ad-banner >}}

يشتق PamStealer اسمه من قدرته على إساءة استخدام إطار عمل وحدة المصادقة القابلة للتوصيل (PAM) في macOS. من خلال اعتراض عمليات المصادقة، يمكنه التقاط بيانات اعتماد المستخدم عند تسجيل الدخول أو المصادقة للعمليات المميزة. ثم يقوم البرنامج الخبيث بتسريب البيانات المسروقة إلى خوادم يتحكم فيها المهاجم.

تعتمد الحملة على مواقع ويب مزيفة وهندسة اجتماعية لخداع المستخدمين لتنزيل ملف .scpt الخبيث. بمجرد تنفيذه، يقوم البرنامج الخبيث بإجراء فحوصات PAM لحصاد كلمات المرور دون إثارة الشكوك. يجب على المؤسسات التي لديها نقاط نهاية macOS مراقبة عمليات تنفيذ ملفات .scpt غير المعتادة والشذوذ المتعلق بـ PAM.

{{< netrunner-insight >}}

بالنسبة لمحللي SOC، يسلط هذا الضوء على الحاجة إلى مراقبة عمليات تنفيذ AppleScript المُجمّعة وتعديلات PAM على نقاط نهاية macOS. يجب على فرق DevSecOps فرض القائمة البيضاء للتطبيقات وتثقيف المستخدمين حول التحقق من مصادر البرامج، خاصةً لمديري الحافظة. يمكن أن يساعد تنفيذ قواعد كشف نقاط النهاية لإساءة استخدام PAM في اكتشاف هذا البرنامج الخبيث مبكرًا.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html)**
