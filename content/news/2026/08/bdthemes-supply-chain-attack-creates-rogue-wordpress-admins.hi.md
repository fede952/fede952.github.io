---
title: "BdThemes सप्लाई चेन अटैक से बने रोग WordPress एडमिन"
date: "2026-08-11T08:10:19Z"
original_date: "2026-08-11T05:48:44"
lang: "hi"
translationKey: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
slug: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
author: "NewsBot (Validated by Federico Sella)"
description: "सप्लाई चेन समझौता BdThemes WordPress प्लगइन्स को प्रभावित करता है; कोई स्रोत कोड संशोधित नहीं, लेकिन दुर्भावनापूर्ण JSON से रोग एडमिन खाते बनते हैं।"
original_url: "https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html"
source: "The Hacker News"
severity: "High"
target: "BdThemes प्लगइन्स का उपयोग करने वाली WordPress साइटें"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

सप्लाई चेन समझौता BdThemes WordPress प्लगइन्स को प्रभावित करता है; कोई स्रोत कोड संशोधित नहीं, लेकिन दुर्भावनापूर्ण JSON से रोग एडमिन खाते बनते हैं।

{{< cyber-report severity="High" source="The Hacker News" target="BdThemes प्लगइन्स का उपयोग करने वाली WordPress साइटें" >}}

साइबर सुरक्षा शोधकर्ताओं ने BdThemes, एक WordPress प्लगइन विक्रेता, को लक्षित करने वाले सप्लाई चेन हमले का खुलासा किया है। इस समझौते के कारण WordPress प्लगइन्स टीम द्वारा प्लगइन डाउनलोड अस्थायी रूप से अक्षम कर दिए गए। विशेष रूप से, यह हमला सामान्य सप्लाई चेन घटनाओं से अलग है: आधिकारिक WordPress.org रिपॉजिटरी के भीतर किसी भी स्रोत कोड फ़ाइल को संशोधित नहीं किया गया था।

{{< ad-banner >}}

इसके बजाय, हमला दुर्भावनापूर्ण JSON पेलोड का उपयोग करके रोग WordPress एडमिन खाते बनाता है। यह तकनीक हमलावरों को कोर प्लगइन फ़ाइलों को बदले बिना प्रभावित साइटों तक अनधिकृत पहुंच प्राप्त करने की अनुमति देती है, जिससे मानक अखंडता जांच के लिए पता लगाना अधिक चुनौतीपूर्ण हो जाता है।

Wordfence शोधकर्ता Paolo Tresso ने हमले की असामान्य प्रकृति पर प्रकाश डाला, इस बात पर जोर देते हुए कि स्रोत कोड संशोधनों की अनुपस्थिति केवल कोड अखंडता से परे व्यापक सप्लाई चेन निगरानी की आवश्यकता को रेखांकित करती है।

{{< netrunner-insight >}}

यह हमला केवल कोड परिवर्तनों की निगरानी के महत्व को नहीं, बल्कि JSON जैसी कॉन्फ़िगरेशन और डेटा फ़ाइलों की भी निगरानी के महत्व को रेखांकित करता है। SOC विश्लेषकों के लिए, प्लगइन अपडेट को उच्च जोखिम वाली घटनाओं के रूप में मानें और केवल स्रोत कोड ही नहीं, बल्कि सभी फ़ाइलों की अखंडता सत्यापित करें। DevSecOps को अप्रत्याशित एडमिन खाता निर्माण के लिए रनटाइम निगरानी लागू करनी चाहिए और गैर-कोड संपत्तियों को कवर करने वाली फ़ाइल अखंडता निगरानी पर विचार करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html)**
