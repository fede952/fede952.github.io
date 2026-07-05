---
title: "TokenLens: أداة فك تشفير JWT وتصحيحه والتحقق من التوقيع"
description: "فك تشفير أي JSON Web Token وتصحيحه داخل متصفحك، ثم تحقّق من توقيعه (HS/RS/ES/PS) تشفيريًا عبر Web Crypto API. يعمل بالكامل على جهة العميل — لا يغادر أي رمز جهازك."
date: 2026-07-05
tags: ["jwt", "developer-tools", "security", "privacy"]
keywords: ["فك تشفير jwt", "تصحيح jwt", "التحقق من توقيع jwt", "json web token", "مدقق jwt", "فك jwt أونلاين", "rs256", "es256", "hs256", "jwt على جهة العميل"]
layout: "tool"
draft: false
tool_file: "/tools/jwt-inspector/"
tool_height: "1200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "TokenLens — أداة فك تشفير JWT والتحقق من التوقيع", "description": "أداة مجانية على جهة العميل لفك تشفير JWT وتصحيح المطالبات والتحقق من التوقيع عبر Web Crypto، تدعم خوارزميات HS وRS وES وPS.", "applicationCategory": "DeveloperApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## ماذا يفعل TokenLens

يفك TokenLens تشفير أي JSON Web Token مباشرةً داخل متصفحك، ويعرض الترويسة والحمولة وكل مطالبة مسجّلة بلغة واضحة — المُصدِر (issuer) والموضوع (subject) والجمهور (audience) والوقت المحلي الدقيق لإصدار الرمز أو بدء صلاحيته أو انتهائها. ثم يمكنك **التحقق من التوقيع تشفيريًا** عبر Web Crypto API باستخدام سرّك أو مفتاحك العام.

بخلاف أدوات فك التشفير على الخادم، لا يغادر الرمز هذه الصفحة أبدًا: بلا رفع، بلا سجلّات، بلا أي طلب شبكي. وهذا بالضبط ما تحتاجه عندما يحمل الرمز مطالبات إنتاجية أو بيانات شخصية ولا يمكن لصقه في خادم طرف آخر.

## الخوارزميات المدعومة

- **HMAC** — HS256 وHS384 وHS512 (التحقق بسرّ مشترك)
- **RSA** — RS256/384/512 وPS256/384/512 (التحقق بمفتاح عام PEM أو JWK)
- **ECDSA** — ES256 وES384 وES512 (التحقق بمفتاح عام EC أو JWK)

الصق رمزًا للبدء، أو حمّل المثال لرؤية توقيع HS256 تم التحقق منه.
