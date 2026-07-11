---
title: "नया MODBEACON RAT एन्क्रिप्टेड C2 ट्रैफिक के लिए gRPC स्ट्रीमिंग का उपयोग करता है"
date: "2026-07-11T08:43:59Z"
original_date: "2026-07-10T13:15:23"
lang: "hi"
translationKey: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
slug: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "चीन से जुड़ा Silver Fox समूह SEO पॉइज़निंग के माध्यम से Rust-आधारित MODBEACON RAT तैनात करता है, एन्क्रिप्टेड C2 संचार के लिए gRPC स्ट्रीमिंग का उपयोग करता है।"
original_url: "https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html"
source: "The Hacker News"
severity: "High"
target: "नकली इंस्टॉलरों के माध्यम से Windows उपयोगकर्ता"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

चीन से जुड़ा Silver Fox समूह SEO पॉइज़निंग के माध्यम से Rust-आधारित MODBEACON RAT तैनात करता है, एन्क्रिप्टेड C2 संचार के लिए gRPC स्ट्रीमिंग का उपयोग करता है।

{{< cyber-report severity="High" source="The Hacker News" target="नकली इंस्टॉलरों के माध्यम से Windows उपयोगकर्ता" >}}

चीन से जुड़े साइबर अपराध समूह Silver Fox को MODBEACON नामक एक नए Rust-आधारित रिमोट एक्सेस ट्रोजन (RAT) से जोड़ा गया है। यह मैलवेयर एन्क्रिप्टेड कमांड-एंड-कंट्रोल (C2) ट्रैफिक के लिए gRPC स्ट्रीमिंग का उपयोग करता है, जिससे इसका पता लगाना अधिक चुनौतीपूर्ण हो जाता है।

{{< ad-banner >}}

चीनी साइबर सुरक्षा कंपनी QiAnXin के अनुसार, Silver Fox SEO पॉइज़निंग तकनीकों का उपयोग करके नकली इंस्टॉलरों के माध्यम से MODBEACON का प्रसार करता है। जबकि यह समूह कम परिष्कार, उच्च गतिविधि वाले ऑपरेशन के रूप में दिखाई दे सकता है, उनकी वास्तविक संगठनात्मक क्षमताएं अधिक उन्नत हैं।

C2 संचार के लिए gRPC स्ट्रीमिंग का उपयोग मैलवेयर के लिए एक नई तकनीक का प्रतिनिधित्व करता है, क्योंकि यह वैध ट्रैफिक के साथ घुलने-मिलने के लिए HTTP/2 और प्रोटोकॉल बफ़र्स का लाभ उठाता है। सुरक्षा टीमों को असामान्य gRPC ट्रैफिक की निगरानी करनी चाहिए और SEO-पॉइज़न किए गए डाउनलोड साइटों की जांच करनी चाहिए।

{{< netrunner-insight >}}

SOC विश्लेषकों को अपनी डिटेक्शन पाइपलाइनों में gRPC ट्रैफिक विश्लेषण जोड़ना चाहिए, क्योंकि MODBEACON का स्ट्रीमिंग RPC का उपयोग पारंपरिक नेटवर्क सिग्नेचर को बायपास कर सकता है। DevSecOps टीमों को सॉफ्टवेयर डाउनलोड की अखंडता सत्यापित करनी चाहिए और ज्ञात SEO पॉइज़निंग डोमेन को ब्लॉक करने पर विचार करना चाहिए। यह RAT Rust-आधारित मैलवेयर के खिलाफ सक्रिय थ्रेट हंटिंग की आवश्यकता को रेखांकित करता है।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html)**
