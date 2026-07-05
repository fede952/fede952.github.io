---
title: "TokenLens: JWT डिकोडर, डीबगर और सिग्नेचर वेरिफायर"
description: "किसी भी JSON Web Token को अपने ब्राउज़र में डिकोड और डीबग करें, फिर Web Crypto API से उसके सिग्नेचर (HS/RS/ES/PS) को क्रिप्टोग्राफ़िक रूप से सत्यापित करें। 100% क्लाइंट-साइड — कोई टोकन आपके डिवाइस से बाहर नहीं जाता।"
date: 2026-07-05
tags: ["jwt", "developer-tools", "security", "privacy"]
keywords: ["jwt डिकोडर", "jwt डीबगर", "jwt सिग्नेचर सत्यापन", "json web token", "jwt वैलिडेटर", "jwt ऑनलाइन डिकोड", "rs256", "es256", "hs256", "क्लाइंट-साइड jwt"]
layout: "tool"
draft: false
tool_file: "/tools/jwt-inspector/"
tool_height: "1200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "TokenLens — JWT डिकोडर और सिग्नेचर वेरिफायर", "description": "HS, RS, ES और PS एल्गोरिद्म का समर्थन करने वाला मुफ़्त क्लाइंट-साइड JWT डिकोडर, क्लेम डीबगर और Web Crypto सिग्नेचर वेरिफायर।", "applicationCategory": "DeveloperApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## TokenLens क्या करता है

TokenLens किसी भी JSON Web Token को सीधे आपके ब्राउज़र में डिकोड करता है और हेडर, पेलोड तथा हर रजिस्टर्ड क्लेम को सरल भाषा में दिखाता है — issuer, subject, audience, और वह सटीक स्थानीय समय जब टोकन जारी हुआ, मान्य होता है या समाप्त होता है। इसके बाद आप अपने स्वयं के सीक्रेट या पब्लिक की से Web Crypto API के ज़रिए **सिग्नेचर को क्रिप्टोग्राफ़िक रूप से सत्यापित** कर सकते हैं।

सर्वर-आधारित डिकोडर के विपरीत, टोकन कभी इस पेज से बाहर नहीं जाता: कोई अपलोड नहीं, कोई लॉग नहीं, कोई नेटवर्क अनुरोध नहीं। जब किसी टोकन में प्रोडक्शन क्लेम या व्यक्तिगत डेटा हो और उसे किसी और के सर्वर पर पेस्ट करना संभव न हो, तो यही आपको चाहिए।

## समर्थित एल्गोरिद्म

- **HMAC** — HS256, HS384, HS512 (साझा सीक्रेट से सत्यापन)
- **RSA** — RS256/384/512 और PS256/384/512 (PEM पब्लिक की या JWK से सत्यापन)
- **ECDSA** — ES256, ES384, ES512 (EC पब्लिक की या JWK से सत्यापन)

शुरू करने के लिए टोकन पेस्ट करें, या सत्यापित HS256 सिग्नेचर देखने के लिए सैंपल लोड करें।
