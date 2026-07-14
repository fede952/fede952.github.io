---
title: "CISA GitHub लीक से छह महीने तक AWS GovCloud कुंजियाँ उजागर"
date: "2026-07-14T09:01:14Z"
original_date: "2026-07-13T15:03:28"
lang: "hi"
translationKey: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
slug: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
author: "NewsBot (Validated by Federico Sella)"
description: "एक ठेकेदार ने छह महीने तक GitHub पर CISA के आंतरिक क्रेडेंशियल, जिनमें AWS GovCloud कुंजियाँ शामिल थीं, लीक कर दीं। विशेषज्ञ सुरक्षा टीमों के लिए महत्वपूर्ण सबक बताते हैं।"
original_url: "https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/"
source: "Krebs on Security"
severity: "High"
target: "CISA GitHub रिपॉजिटरी"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

एक ठेकेदार ने छह महीने तक GitHub पर CISA के आंतरिक क्रेडेंशियल, जिनमें AWS GovCloud कुंजियाँ शामिल थीं, लीक कर दीं। विशेषज्ञ सुरक्षा टीमों के लिए महत्वपूर्ण सबक बताते हैं।

{{< cyber-report severity="High" source="Krebs on Security" target="CISA GitHub रिपॉजिटरी" >}}

साइबर सुरक्षा और बुनियादी ढांचा सुरक्षा एजेंसी (CISA) ने एक डेटा लीक का खुलासा किया, जिसमें एक ठेकेदार ने अनजाने में दर्जनों आंतरिक क्रेडेंशियल, जिनमें AWS GovCloud कुंजियाँ शामिल थीं, एक सार्वजनिक GitHub रिपॉजिटरी में प्रकाशित कर दिए। ये क्रेडेंशियल लगभग छह महीने तक उजागर रहे, जब तक KrebsOnSecurity ने एजेंसी को सूचित नहीं किया।

{{< ad-banner >}}

CISA की पोस्टमार्टम रिपोर्ट में उनकी प्रारंभिक प्रतिक्रिया में कमियों की पहचान की गई, जैसे विलंबित पहचान और सार्वजनिक रिपॉजिटरी में रहस्यों के लिए स्वचालित स्कैनिंग की कमी। यह घटना मजबूत गुप्त प्रबंधन और कोड रिपॉजिटरी की निरंतर निगरानी की आवश्यकता को रेखांकित करती है।

विशेषज्ञ प्री-कमिट हुक, नियमित गुप्त स्कैनिंग और सख्त पहुँच नियंत्रण लागू करने की सलाह देते हैं ताकि इसी तरह के लीक को रोका जा सके। अस्थायी क्रेडेंशियल और स्वचालित रोटेशन का उपयोग उजागर कुंजियों के प्रभाव को कम कर सकता है।

{{< netrunner-insight >}}

यह घटना इस बात का एक पाठ्यपुस्तक उदाहरण है कि क्यों गुप्त स्कैनिंग को CI/CD पाइपलाइनों में एकीकृत किया जाना चाहिए, न कि केवल पोस्ट-कमिट। SOC विश्लेषकों को सार्वजनिक रिपॉजिटरी एक्सपोज़र के लिए अलर्ट को प्राथमिकता देनी चाहिए, और DevSecOps टीमों को ठेकेदारों के लिए न्यूनतम-विशेषाधिकार पहुँच लागू करनी चाहिए। क्रेडेंशियल रोटेशन को स्वचालित करें और लीक को जल्दी पकड़ने के लिए GitLeaks या TruffleHog जैसे टूल का उपयोग करने पर विचार करें।

{{< /netrunner-insight >}}

---

**[पूरा लेख Krebs on Security पर पढ़ें ›](https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/)**
