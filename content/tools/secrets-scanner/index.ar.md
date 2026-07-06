---
title: "SafeEnv: فاحص الأسرار ومفاتيح API لملفات .env"
description: "افحص ملفات .env ومقاطع الإعدادات بحثًا عن أسرار مكشوفة قبل عمل commit — مفاتيح AWS، رموز GitHub وStripe، المفاتيح الخاصة، كلمات المرور داخل الروابط والقيم عالية الإنتروبيا. يعمل 100% في متصفحك: لا يُرفع أي شيء أبدًا."
date: 2026-07-05
tags: ["security", "developer-tools", "secrets", "privacy"]
keywords: ["فاحص ملف env", "فاحص الأسرار", "فحص مفاتيح api", "اكتشاف الأسرار المسربة", "فحص env", "تسرب مفاتيح aws", "git secrets", "فاحص أسرار على جهة العميل", "أمان dotenv"]
layout: "tool"
draft: false
tool_file: "/tools/secrets-scanner/"
tool_height: "1150"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "SafeEnv — فاحص الأسرار ومفاتيح API", "description": "فاحص مجاني على جهة العميل يعثر على مفاتيح API والرموز والمفاتيح الخاصة وكلمات المرور المكشوفة في ملفات .env والإعدادات قبل الـ commit.", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## لماذا الفحص قبل الـ commit

يكفي ملف `.env` واحد يُلصق في مستودع عام: تمسح الروبوتات GitHub وتعثر على مفاتيح AWS الجديدة في **أقل من دقيقة**. يلتقط SafeEnv التسريب قبل الـ commit. الصق أي إعدادات — `.env` أو `docker-compose.yml` أو إعدادات CI أو مقاطع شيفرة — وسيحدد بيانات الاعتماد المكشوفة مع رقم السطر ومعاينة مقنّعة وخطوات معالجة عملية.

يجري الفحص بالكامل داخل ذاكرة هذه الصفحة. بلا رفع، بلا سجلات، بلا أي طلب شبكي — وهذا هو التصميم الوحيد المقبول لأداة تلصق فيها أسرارًا حقيقية. أعد تحميل الصفحة فيختفي كل شيء.

## ما الذي يكتشفه

- **رموز السحابة وAPI** — مفاتيح AWS وGitHub وGitLab وStripe وGoogle وOpenAI وAnthropic وSlack وSendGrid وnpm وPyPI وTelegram وTwilio
- **المفاتيح الخاصة** — كتل PEM بأنواع RSA/EC/OpenSSH/PGP
- **بيانات اعتماد داخل الروابط** — سلاسل اتصال قواعد البيانات وروابط basic-auth بكلمات مرور مضمّنة
- **تسريبات عامة** — كلمات مرور مكتوبة في الشيفرة وقيم عالية الإنتروبيا، مع التعرف على القيم النائبة لتقليل الإنذارات الخاطئة

الصق إعداداتك لفحصها، أو حمّل المثال لترى كل الكواشف تعمل على مفاتيح وهمية.
