---
title: "'Certighost' खामी माइक्रोसॉफ्ट एक्टिव डायरेक्ट्री प्रमाणपत्रों को परेशान करती है"
date: "2026-07-29T09:36:19Z"
original_date: "2026-07-28T16:38:48"
lang: "hi"
translationKey: "certighost-flaw-haunts-microsoft-active-directory-certificates"
slug: "certighost-flaw-haunts-microsoft-active-directory-certificates"
author: "NewsBot (Validated by Federico Sella)"
description: "माइक्रोसॉफ्ट ने एक उच्च-गंभीरता वाली कमजोरी को पैच किया जो एक्टिव डायरेक्ट्री वातावरण में विशेषाधिकार वृद्धि की अनुमति देती है। SOC विश्लेषकों को पैचिंग को प्राथमिकता देनी चाहिए।"
original_url: "https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates"
source: "Dark Reading"
severity: "High"
target: "माइक्रोसॉफ्ट एक्टिव डायरेक्ट्री सर्टिफिकेट सर्विसेज"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

माइक्रोसॉफ्ट ने एक उच्च-गंभीरता वाली कमजोरी को पैच किया जो एक्टिव डायरेक्ट्री वातावरण में विशेषाधिकार वृद्धि की अनुमति देती है। SOC विश्लेषकों को पैचिंग को प्राथमिकता देनी चाहिए।

{{< cyber-report severity="High" source="Dark Reading" target="माइक्रोसॉफ्ट एक्टिव डायरेक्ट्री सर्टिफिकेट सर्विसेज" >}}

माइक्रोसॉफ्ट ने एक्टिव डायरेक्ट्री सर्टिफिकेट सर्विसेज में 'Certighost' नामक एक उच्च-गंभीरता वाली कमजोरी को पैच किया है, जो एक हमलावर को विशेषाधिकार बढ़ाने और एक्टिव डायरेक्ट्री वातावरण से समझौता करने की अनुमति दे सकती है। इस खामी का खुलासा 28 जुलाई, 2026 को Dark Reading द्वारा किया गया था।

{{< ad-banner >}}

यह कमजोरी प्रमाणपत्र नामांकन प्रक्रिया को प्रभावित करती है, जिससे कम-स्तरीय पहुंच वाला एक खतरा अभिनेता अपने विशेषाधिकारों को डोमेन प्रशासक तक बढ़ा सकता है। इससे AD बुनियादी ढांचे का पूर्ण समझौता हो सकता है, जिसमें प्रमाणपत्र जाली बनाने और किसी भी उपयोगकर्ता या डिवाइस का प्रतिरूपण करने की क्षमता शामिल है।

माइक्रोसॉफ्ट एक्टिव डायरेक्ट्री सर्टिफिकेट सर्विसेज का उपयोग करने वाले संगठनों को तुरंत नवीनतम सुरक्षा अपडेट लागू करने की सलाह दी जाती है। यह कमजोरी AD वातावरण में विश्वास बनाए रखने में प्रमाणपत्र सेवाओं के महत्वपूर्ण स्वरूप को रेखांकित करती है।

{{< netrunner-insight >}}

यह एक क्लासिक AD प्रमाणपत्र सेवा हमला वेक्टर है। सुनिश्चित करें कि आपके प्रमाणपत्र टेम्पलेट कठोर हैं और नामांकन अनुमतियाँ कसकर नियंत्रित हैं। तुरंत पैच करें और असामान्य प्रमाणपत्र अनुरोधों या विशेषाधिकार वृद्धियों की निगरानी करें।

{{< /netrunner-insight >}}

---

**[पूरा लेख Dark Reading पर पढ़ें ›](https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates)**
