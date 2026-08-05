---
title: "هجوم سلسلة التوريد على QuickFox يوزع بابًا خلفيًا FDMTP عبر مثبت معدل"
date: "2026-08-05T09:34:12Z"
original_date: "2026-08-05T05:47:19"
lang: "ar"
translationKey: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
slug: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
author: "NewsBot (Validated by Federico Sella)"
description: "هجوم طويل الأمد على سلسلة التوريد لـ QuickFox VPN يحول المثبت إلى برنامج ضار لنشر باب خلفي FDMTP، مستهدفًا المستخدمين الصينيين في الخارج منذ أغسطس 2025."
original_url: "https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html"
source: "The Hacker News"
severity: "High"
target: "مستخدمو QuickFox VPN"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

هجوم طويل الأمد على سلسلة التوريد لـ QuickFox VPN يحول المثبت إلى برنامج ضار لنشر باب خلفي FDMTP، مستهدفًا المستخدمين الصينيين في الخارج منذ أغسطس 2025.

{{< cyber-report severity="High" source="The Hacker News" target="مستخدمو QuickFox VPN" >}}

كشفت Fortinet FortiGuard Labs عن هجوم طويل الأمد على سلسلة التوريد يستهدف QuickFox، وهي أداة VPN وتسريع الشبكة شائعة بين المستخدمين الصينيين في الخارج. الهجوم، النشط منذ أغسطس 2025 على الأقل، يتضمن نسخة معدلة من مثبت Windows للتطبيق تقوم بتسليم باب خلفي يُدعى FDMTP.

{{< ad-banner >}}

يتم توزيع المثبت المعدل عبر قنوات رسمية أو موثوقة، مما يعرض سلامة سلسلة التوريد للخطر. بمجرد تنفيذه، يوفر FDMTP للمهاجمين وصولاً وتحكمًا عن بُعد في نظام الضحية، مما قد يؤدي إلى سرقة البيانات أو التجسس أو نشر برامج ضارة إضافية.

يسلط هذا الحادث الضوء على المخاطر المتزايدة لهجمات سلسلة التوريد على الأدوات المتخصصة ولكن الموثوقة، خاصة تلك التي تخدم مجتمعات محددة. يجب على المؤسسات والأفراد الذين يستخدمون QuickFox التحقق من سلامة تثبيتاتهم ومراقبة مؤشرات الاختراق المرتبطة بـ FDMTP.

{{< netrunner-insight >}}

يؤكد هذا الهجوم على الحاجة إلى تحقق قوي من سلامة البرامج، حتى بالنسبة للأدوات من بائعين يبدون موثوقين. يجب على محللي SOC البحث عن مؤشرات FDMTP ومراقبة الاتصالات الشبكية غير العادية من عملاء VPN. يجب على فرق DevSecOps فرض التحقق من توقيع الكود والتجزئة في خطوط نشر البرامج الخاصة بهم للتخفيف من مخاطر سلسلة التوريد هذه.

{{< /netrunner-insight >}}

---

**[اقرأ المقال كاملاً على The Hacker News ›](https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html)**
