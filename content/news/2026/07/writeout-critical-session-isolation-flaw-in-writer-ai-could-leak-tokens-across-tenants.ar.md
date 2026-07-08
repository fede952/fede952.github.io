---
title: "WriteOut: ثغرة خطيرة في عزل الجلسات في Writer AI قد تؤدي إلى تسرب الرموز عبر المستأجرين"
date: "2026-07-08T09:23:55Z"
original_date: "2026-07-07T13:27:09"
lang: "ar"
translationKey: "writeout-critical-session-isolation-flaw-in-writer-ai-could-leak-tokens-across-tenants"
slug: "writeout-critical-session-isolation-flaw-in-writer-ai-could-leak-tokens-across-tenants"
author: "NewsBot (Validated by Federico Sella)"
description: "ثغرة بنقرة واحدة في Writer AI، تحمل الاسم الرمزي WriteOut، قد تسمح بتسرب رموز الجلسة عبر المستأجرين. تم إصلاح الثغرة الآن."
original_url: "https://thehackernews.com/2026/07/writer-ai-flaw-could-let-agent-previews.html"
source: "The Hacker News"
severity: "Critical"
target: "منصة Writer AI للمؤسسات"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ثغرة بنقرة واحدة في Writer AI، تحمل الاسم الرمزي WriteOut، قد تسمح بتسرب رموز الجلسة عبر المستأجرين. تم إصلاح الثغرة الآن.

{{< cyber-report severity="Critical" source="The Hacker News" target="منصة Writer AI للمؤسسات" >}}

كشف باحثو الأمن السيبراني في Sand Security عن ثغرة خطيرة في عزل الجلسات في Writer، وهي منصة ذكاء اصطناعي توليدية للمؤسسات. الثغرة، المسماة WriteOut، قد تمكن المهاجم من تسريب رموز الجلسة عبر المستأجرين، مما يؤدي إلى اختراق عبر المستأجرين بنقرة واحدة.

{{< ad-banner >}}

تنشأ الثغرة من عزل غير صحيح للجلسات في ميزة معاينة الوكيل، مما يسمح لشخص خارجي بالتصعيد من عدم الوصول إلى السيطرة الكاملة على أي مستأجر في Writer AI. قامت Writer منذ ذلك الحين بإصلاح المشكلة، لكن الاكتشاف يسلط الضوء على مخاطر منصات الذكاء الاصطناعي متعددة المستأجرين.

يجب على المؤسسات التي تستخدم Writer AI التحقق من تطبيق أحدث التصحيحات ومراجعة إعدادات إدارة الجلسات. تعتبر ثغرة WriteOut تذكيرًا بأهمية إعطاء الأولوية لعزل المستأجرين في خدمات الذكاء الاصطناعي السحابية.

{{< netrunner-insight >}}

لمحللي SOC: راقب استخدام رموز الجلسة الشاذة وأنماط الوصول عبر المستأجرين في سجلات Writer AI. يجب على فرق DevSecOps فرض عزل صارم للجلسات والنظر في تنفيذ فحوصات إضافية لحدود المستأجرين في نشرات الذكاء الاصطناعي متعددة المستأجرين.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/07/writer-ai-flaw-could-let-agent-previews.html)**
