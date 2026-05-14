---
title: "क्रिटिकल Exim मेलर दोष रिमोट कोड निष्पादन की अनुमति देता है"
date: "2026-05-14T09:33:22Z"
original_date: "2026-05-13T20:23:50"
lang: "hi"
translationKey: "critical-exim-mailer-flaw-allows-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "Exim मेल ट्रांसफर एजेंट कॉन्फ़िगरेशन में एक गंभीर कमजोरी अनधिकृत हमलावरों को दूरस्थ रूप से मनमाना कोड निष्पादित करने दे सकती है। तुरंत पैच लगाएं।"
original_url: "https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/"
source: "BleepingComputer"
severity: "Critical"
target: "Exim मेल ट्रांसफर एजेंट"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Exim मेल ट्रांसफर एजेंट कॉन्फ़िगरेशन में एक गंभीर कमजोरी अनधिकृत हमलावरों को दूरस्थ रूप से मनमाना कोड निष्पादित करने दे सकती है। तुरंत पैच लगाएं।

{{< cyber-report severity="Critical" source="BleepingComputer" target="Exim मेल ट्रांसफर एजेंट" >}}

Exim ओपन-सोर्स मेल ट्रांसफर एजेंट में एक गंभीर कमजोरी पाई गई है जो कुछ कॉन्फ़िगरेशन को प्रभावित करती है। यह दोष एक अनधिकृत दूरस्थ हमलावर को कमजोर सिस्टम पर मनमाना कोड निष्पादित करने की अनुमति दे सकता है।

{{< ad-banner >}}

Exim का उपयोग Unix-जैसे सिस्टम पर मेल सर्वर के रूप में व्यापक रूप से किया जाता है, जिससे यह कमजोरी उन संगठनों के लिए विशेष रूप से चिंताजनक है जो ईमेल वितरण के लिए इस पर निर्भर हैं। शोषण के सटीक तकनीकी विवरण पूरी तरह से सार्वजनिक नहीं किए गए हैं, लेकिन गंभीरता रेटिंग तत्काल पैचिंग की सिफारिश करती है।

प्रशासकों को अपने Exim कॉन्फ़िगरेशन की समीक्षा करनी चाहिए और Exim प्रोजेक्ट से उपलब्ध किसी भी अपडेट को लागू करना चाहिए। पैच तैनात होने तक, कमजोर सेवा के संपर्क को सीमित करने के लिए नेटवर्क-स्तरीय पहुंच नियंत्रण लागू करने पर विचार करें।

{{< netrunner-insight >}}

यह व्यापक रूप से तैनात MTA में एक गंभीर रिमोट कोड निष्पादन वेक्टर है। SOC विश्लेषकों को Exim इंस्टेंस के लिए स्कैनिंग को प्राथमिकता देनी चाहिए और कॉन्फ़िगरेशन हार्डनिंग को सत्यापित करना चाहिए। DevSecOps टीमों को पैचिंग में तेजी लानी चाहिए और अपडेट लागू होने तक शोषण प्रयासों को ब्लॉक करने के लिए WAF नियमों पर विचार करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/)**
