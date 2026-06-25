---
title: "Cordyceps CI/CD खामियों से 300+ GitHub रिपॉजिटरी को खतरा"
date: "2026-06-25T10:14:17Z"
original_date: "2026-06-24T12:48:11"
lang: "hi"
translationKey: "cordyceps-ci-cd-flaws-threaten-300-github-repos"
author: "NewsBot (Validated by Federico Sella)"
description: "Cordyceps कोडनेम वाली नई CI/CD वर्कफ़्लो कमजोरी हमलावरों को वर्कफ़्लो हाईजैक करने और बड़े संगठनों में ओपन-सोर्स सप्लाई चेन से समझौता करने की अनुमति देती है।"
original_url: "https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html"
source: "The Hacker News"
severity: "Critical"
target: "GitHub पर CI/CD वर्कफ़्लो"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Cordyceps कोडनेम वाली नई CI/CD वर्कफ़्लो कमजोरी हमलावरों को वर्कफ़्लो हाईजैक करने और बड़े संगठनों में ओपन-सोर्स सप्लाई चेन से समझौता करने की अनुमति देती है।

{{< cyber-report severity="Critical" source="The Hacker News" target="GitHub पर CI/CD वर्कफ़्लो" >}}

Novee Security के साइबर सुरक्षा शोधकर्ताओं ने CI/CD वर्कफ़्लो में एक गंभीर शोषणीय पैटर्न की पहचान की है, जिसे Cordyceps नाम दिया गया है, जो हमलावरों को वर्कफ़्लो हाईजैक करने और ओपन-सोर्स सप्लाई चेन से समझौता करने की अनुमति देता है। यह खामी Microsoft, Google और Apache सहित प्रमुख संगठनों की 300 से अधिक GitHub रिपॉजिटरी को प्रभावित करती है।

{{< ad-banner >}}

Cordyceps पैटर्न रिपॉजिटरी पर हमलावर का पूर्ण नियंत्रण सक्षम बनाता है, जिससे अनधिकृत कोड परिवर्तन, बैकडोर सम्मिलन और डाउनस्ट्रीम सप्लाई-चेन हमले हो सकते हैं। यह कमजोरी असुरक्षित वर्कफ़्लो कॉन्फ़िगरेशन से उत्पन्न होती है जो इनपुट को ठीक से अलग या मान्य नहीं करते हैं।

GitHub Actions या समान CI/CD प्लेटफ़ॉर्म का उपयोग करने वाले संगठनों से आग्रह किया जाता है कि वे Cordyceps पैटर्न के लिए अपनी वर्कफ़्लो परिभाषाओं की समीक्षा करें और जोखिम को कम करने के लिए न्यूनतम-विशेषाधिकार अनुमतियाँ, इनपुट स्वच्छता और पर्यावरण पृथक्करण लागू करें।

{{< netrunner-insight >}}

यह एक पाठ्यपुस्तकीय सप्लाई-चेन हमला वेक्टर है। SOC विश्लेषकों को असामान्य वर्कफ़्लो निष्पादन और अप्रत्याशित रिपॉजिटरी परिवर्तनों की निगरानी करनी चाहिए। DevSecOps टीमों को तुरंत CI/CD पाइपलाइन कॉन्फ़िगरेशन का ऑडिट करना चाहिए, जिसमें अविश्वसनीय इनपुट हैंडलिंग और अनुमति स्कोपिंग पर ध्यान केंद्रित किया जाए।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)**
