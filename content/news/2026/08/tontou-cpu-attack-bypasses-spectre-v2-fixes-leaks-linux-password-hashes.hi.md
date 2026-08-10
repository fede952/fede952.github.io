---
title: "TONTOU CPU हमला Spectre v2 सुधारों को बायपास करता है, Linux पासवर्ड हैश लीक करता है"
date: "2026-08-10T08:26:15Z"
original_date: "2026-08-06T18:03:45"
lang: "hi"
translationKey: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
slug: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "शोधकर्ताओं ने TONTOU हमला विकसित किया है जो हाल के Spectre v2 शमन उपायों को बायपास करता है, जिससे Linux सिस्टम से पासवर्ड हैश सहित गोपनीय जानकारी सफलतापूर्वक लीक होती है।"
original_url: "https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/"
source: "BleepingComputer"
severity: "High"
target: "Linux सिस्टम"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

शोधकर्ताओं ने TONTOU हमला विकसित किया है जो हाल के Spectre v2 शमन उपायों को बायपास करता है, जिससे Linux सिस्टम से पासवर्ड हैश सहित गोपनीय जानकारी सफलतापूर्वक लीक होती है।

{{< cyber-report severity="High" source="BleepingComputer" target="Linux सिस्टम" >}}

सुरक्षा शोधकर्ताओं ने एक नया स्पेक्युलेटिव एक्ज़ीक्यूशन हमला उजागर किया है, जिसे TONTOU नाम दिया गया है, जो Spectre v2 भेद्यता के हालिया शमन उपायों को दरकिनार करता है। यह हमला CPU की ब्रांच प्रेडिक्शन तंत्र को लक्षित करता है, जिसे पहले साइड-चैनल लीक को रोकने के लिए पैच किया गया था। इन सुरक्षा उपायों में एक अंतर का फायदा उठाकर, शोधकर्ता Linux मशीनों के कर्नेल मेमोरी से संवेदनशील डेटा निकालने में सक्षम थे।

{{< ad-banner >}}

प्रूफ-ऑफ-कॉन्सेप्ट एक्सप्लॉइट लक्षित सिस्टम से पासवर्ड हैश को सफलतापूर्वक लीक करके समस्या की गंभीरता को प्रदर्शित करता है। यह इंगित करता है कि इस हमले का उपयोग उपयोगकर्ता क्रेडेंशियल्स से समझौता करने और संभावित रूप से विशेषाधिकार बढ़ाने के लिए किया जा सकता है। निष्कर्ष स्पेक्युलेटिव एक्ज़ीक्यूशन साइड-चैनल हमलों को पूरी तरह से कम करने की चुनौती को उजागर करते हैं, क्योंकि पिछले सुधारों के बावजूद नए रूप सामने आते रहते हैं।

जबकि शोधकर्ताओं ने अभी तक पूर्ण तकनीकी विवरण जारी नहीं किए हैं, उनका काम CPU सुरक्षा में निरंतर सतर्कता की आवश्यकता को रेखांकित करता है। सिस्टम प्रशासकों को सलाह दी जाती है कि वे CPU विक्रेताओं और Linux वितरणों से अपडेट की निगरानी करें, और कर्नेल एड्रेस स्पेस लेआउट रैंडमाइजेशन (KASLR) और माइक्रोकोड अपडेट जैसे अतिरिक्त सख्तीकरण उपायों पर विचार करें।

{{< netrunner-insight >}}

यह हमला एक स्पष्ट अनुस्मारक है कि स्पेक्युलेटिव एक्ज़ीक्यूशन भेद्यताएं पूरी तरह से हल नहीं हुई हैं। SOC विश्लेषकों को पैचिंग को प्राथमिकता देनी चाहिए और शोषण के किसी भी संकेत के लिए निगरानी करनी चाहिए, जबकि DevSecOps इंजीनियरों को साइड-चैनल जोखिमों के लिए अपने खतरे के मॉडल की समीक्षा करनी चाहिए। पासवर्ड हैश लीक करने की क्षमता को देखते हुए, Linux कर्नेल अपडेट और CPU माइक्रोकोड पर तत्काल ध्यान देना आवश्यक है।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/)**
