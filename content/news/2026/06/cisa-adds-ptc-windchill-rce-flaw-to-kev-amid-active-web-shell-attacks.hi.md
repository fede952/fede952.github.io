---
title: "CISA ने सक्रिय वेब शेल हमलों के बीच PTC Windchill RCE दोष को KEV में जोड़ा"
date: "2026-06-27T09:25:09Z"
original_date: "2026-06-26T12:31:56"
lang: "hi"
translationKey: "cisa-adds-ptc-windchill-rce-flaw-to-kev-amid-active-web-shell-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA ने सक्रिय शोषण के कारण PTC Windchill PDMlink और FlexPLM में एक महत्वपूर्ण रिमोट कोड निष्पादन भेद्यता को अपनी ज्ञात शोषित भेद्यताओं की सूची में जोड़ा।"
original_url: "https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html"
source: "The Hacker News"
severity: "Critical"
target: "PTC Windchill PDMlink और FlexPLM"
cve: null
cvss: null
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA ने सक्रिय शोषण के कारण PTC Windchill PDMlink और FlexPLM में एक महत्वपूर्ण रिमोट कोड निष्पादन भेद्यता को अपनी ज्ञात शोषित भेद्यताओं की सूची में जोड़ा।

{{< cyber-report severity="Critical" source="The Hacker News" target="PTC Windchill PDMlink और FlexPLM" kev="true" >}}

अमेरिकी साइबर सुरक्षा और बुनियादी ढांचा सुरक्षा एजेंसी (CISA) ने PTC Windchill PDMlink और PTC FlexPLM को प्रभावित करने वाली एक महत्वपूर्ण रिमोट कोड निष्पादन भेद्यता को अपनी ज्ञात शोषित भेद्यताओं (KEV) सूची में जोड़ा है। यह निर्णय सक्रिय शोषण के सबूतों के बाद लिया गया है, जिसमें रिपोर्टों से संकेत मिलता है कि इन एंटरप्राइज उत्पाद डेटा प्रबंधन (PDM) और उत्पाद जीवनचक्र प्रबंधन (PLM) सिस्टम को लक्षित करने वाले वेब शेल हमले जारी हैं।

{{< ad-banner >}}

जबकि घोषणा में विशिष्ट CVE पहचानकर्ता का खुलासा नहीं किया गया, भेद्यता को एक महत्वपूर्ण RCE दोष के रूप में वर्णित किया गया है जो हमलावरों को प्रभावित सिस्टम पर मनमाना कोड निष्पादित करने की अनुमति दे सकता है। इन उत्पादों का उपयोग करने वाले संगठनों से पैचिंग को प्राथमिकता देने और समझौते के संकेतों के लिए अपने वातावरण की समीक्षा करने का आग्रह किया जाता है, क्योंकि शोषण से पूर्ण सिस्टम अधिग्रहण हो सकता है।

CISA की KEV सूची संघीय एजेंसियों के लिए एक बाध्यकारी परिचालन निर्देश के रूप में कार्य करती है, जिसमें निर्दिष्ट समयसीमा के भीतर सुधार की आवश्यकता होती है। निजी क्षेत्र के संगठनों को दृढ़ता से सलाह दी जाती है कि वे इसे उच्च-प्राथमिकता वाले खतरे के रूप में मानें और नेटवर्क विभाजन और असामान्य वेब शेल गतिविधि की निगरानी जैसे उपायों को लागू करें।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, एक्सपोज़्ड Windchill सर्वरों पर वेब शेल संकेतकों की खोज को प्राथमिकता दें—एप्लिकेशन द्वारा उत्पन्न असामान्य चाइल्ड प्रोसेस या अज्ञात IP से बाहरी कनेक्शन देखें। DevSecOps टीमों को तुरंत उपलब्ध पैच लागू करना चाहिए और यदि पैचिंग में देरी हो तो वर्चुअल पैचिंग या WAF नियम तैनात करने पर विचार करना चाहिए। यह एक अनुस्मारक है कि PLM सिस्टम, जिन्हें अक्सर पैच प्रबंधन में अनदेखा किया जाता है, रैनसमवेयर समूहों के लिए आकर्षक लक्ष्य हैं।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html)**
