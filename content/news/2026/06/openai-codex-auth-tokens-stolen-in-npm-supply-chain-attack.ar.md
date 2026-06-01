---
title: "سرقة رموز مصادقة OpenAI Codex في هجوم على سلسلة توريد npm"
date: "2026-06-01T12:34:23Z"
original_date: "2026-06-01T09:31:15"
lang: "ar"
translationKey: "openai-codex-auth-tokens-stolen-in-npm-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "حزمة npm الخبيثة codexui-android تستهدف المطورين، وتسرق رموز مصادقة OpenAI Codex مع أكثر من 29,000 تنزيل أسبوعي."
original_url: "https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html"
source: "The Hacker News"
severity: "High"
target: "مطورو OpenAI Codex"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

حزمة npm الخبيثة codexui-android تستهدف المطورين، وتسرق رموز مصادقة OpenAI Codex مع أكثر من 29,000 تنزيل أسبوعي.

{{< cyber-report severity="High" source="The Hacker News" target="مطورو OpenAI Codex" >}}

كشف باحثو الأمن السيبراني عن حملة خبيثة في سلسلة التوريد تستهدف المطورين الذين يستخدمون OpenAI Codex. يعتمد الهجوم على حزمة npm تبدو شرعية باسم codexui-android، والتي تُعلن كواجهة ويب عن بعد لـ OpenAI Codex على كل من GitHub و npm. وقد جذبت الحزمة أكثر من 29,000 تنزيل أسبوعي، مما يشير إلى وصول كبير داخل مجتمع المطورين.

{{< ad-banner >}}

تم تصميم الحزمة الخبيثة لسرقة رموز مصادقة OpenAI Codex من المطورين غير المنتبهين. وحتى وقت التقرير، لا تزال الحزمة متاحة للتنزيل، مما يشكل تهديدًا مستمرًا. يُنصح المطورون الذين قاموا بتثبيت codexui-android بتدوير رموزهم فورًا ومراجعة أنظمتهم بحثًا عن وصول غير مصرح به.

تسلط هذه الحادثة الضوء على المخاطر المستمرة لهجمات سلسلة التوريد في النظام البيئي مفتوح المصدر. يمكن أن يؤدي استخدام أسماء حزم تبدو شرعية وأعداد تنزيلات عالية إلى إعطاء المطورين شعورًا زائفًا بالأمان. يجب على المؤسسات تنفيذ عمليات فحص صارمة للحزم والنظر في استخدام أدوات تكتشف سلوك الحزم الشاذ.

{{< netrunner-insight >}}

لمحللي SOC ومهندسي DevSecOps، يؤكد هذا الهجوم على ضرورة مراقبة تنزيلات وسلوك حزم npm. قم بتنفيذ كشف وقت التشغيل لتسرب الرموز غير المتوقع وفرض صلاحيات الوصول الأقل امتيازًا لرموز API. قم بمراجعة سلسلة توريد البرامج الخاصة بك بانتظام وفكر في استخدام أدوات التحقق من سلامة الحزم.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html)**
