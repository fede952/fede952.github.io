---
title: "अनपैच्ड विंडोज सर्च URI दोष से NTLMv2 हैश लीक"
date: "2026-06-03T11:53:18Z"
original_date: "2026-06-03T10:18:52"
lang: "hi"
translationKey: "unpatched-windows-search-uri-flaw-leaks-ntlmv2-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "शोधकर्ताओं ने विंडोज सर्च: URI हैंडलर में एक अनपैच्ड कमजोरी का खुलासा किया है जो NTLMv2 हैश को उजागर कर सकती है, जो CVE-2026-33829 स्निपिंग टूल दोष के समान है।"
original_url: "https://thehackernews.com/2026/06/unpatched-windows-search-uri.html"
source: "The Hacker News"
severity: "High"
target: "विंडोज सर्च: URI हैंडलर"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

शोधकर्ताओं ने विंडोज सर्च: URI हैंडलर में एक अनपैच्ड कमजोरी का खुलासा किया है जो NTLMv2 हैश को उजागर कर सकती है, जो CVE-2026-33829 स्निपिंग टूल दोष के समान है।

{{< cyber-report severity="High" source="The Hacker News" target="विंडोज सर्च: URI हैंडलर" >}}

Huntress के साइबर सुरक्षा शोधकर्ताओं ने विंडोज सर्च: URI हैंडलर में एक अनपैच्ड कमजोरी का विवरण साझा किया है जो हमलावरों को NTLMv2 हैश चुराने की अनुमति दे सकती है। यह समस्या CVE-2026-33829 की याद दिलाती है, जो विंडोज स्निपिंग टूल के ms-screensketch: URI हैंडलर में एक स्पूफिंग कमजोरी थी जो NTLM हैश को भी उजागर करती थी।

{{< ad-banner >}}

नव पहचाना गया दोष search: URI स्कीम में है, जिसका उपयोग विंडोज सर्च क्वेरी चलाने के लिए किया जाता है। एक दुर्भावनापूर्ण लिंक या फ़ाइल बनाकर जो search: URI हैंडलर को ट्रिगर करती है, एक हमलावर लक्ष्य सिस्टम को एक रिमोट सर्वर पर प्रमाणित करने के लिए मजबूर कर सकता है, जिससे उपयोगकर्ता का NTLMv2 हैश लीक हो जाता है। इस हैश को ऑफलाइन क्रैक किया जा सकता है या रिले हमलों में उपयोग किया जा सकता है।

प्रकाशन तिथि तक, Microsoft द्वारा कोई आधिकारिक पैच जारी नहीं किया गया है। संगठनों को अपडेट की निगरानी करने और फिक्स उपलब्ध होने तक ग्रुप पॉलिसी या एंडपॉइंट सुरक्षा उपकरणों के माध्यम से search: URI हैंडलर को ब्लॉक करने पर विचार करने की सलाह दी जाती है।

{{< netrunner-insight >}}

यह एक क्लासिक NTLM रिले वेक्टर है जिसे SOC विश्लेषकों को प्रमाणीकरण लॉग में देखना चाहिए। DevSecOps इंजीनियरों को तुरंत अपने वातावरण में URI हैंडलर के किसी भी उपयोग की समीक्षा करनी चाहिए और NTLMv2 को अक्षम करने या SMB साइनिंग लागू करने जैसे शमन उपायों को लागू करने पर विचार करना चाहिए। जब तक Microsoft इसे पैच नहीं करता, तब तक search: URI को क्रेडेंशियल चोरी के लिए एक संभावित प्रवेश बिंदु मानें।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/06/unpatched-windows-search-uri.html)**
