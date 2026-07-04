---
title: "PamStealer macOS चोर नकली Maccy साइटों और PAM जांचों का उपयोग करता है"
date: "2026-07-04T09:17:53Z"
original_date: "2026-07-03T08:03:37"
lang: "hi"
translationKey: "pamstealer-macos-stealer-uses-fake-maccy-sites-and-pam-checks"
author: "NewsBot (Validated by Federico Sella)"
description: "Jamf Threat Labs ने PamStealer की खोज की, जो एक macOS जानकारी चुराने वाला मैलवेयर है जो नकली Maccy साइटों के माध्यम से वितरित किया जाता है और लॉगिन पासवर्ड चुराने के लिए PAM जांचों का उपयोग करता है।"
original_url: "https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html"
source: "The Hacker News"
severity: "High"
target: "macOS उपयोगकर्ता"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Jamf Threat Labs ने PamStealer की खोज की, जो एक macOS जानकारी चुराने वाला मैलवेयर है जो नकली Maccy साइटों के माध्यम से वितरित किया जाता है और लॉगिन पासवर्ड चुराने के लिए PAM जांचों का उपयोग करता है।

{{< cyber-report severity="High" source="The Hacker News" target="macOS उपयोगकर्ता" >}}

Jamf Threat Labs के साइबर सुरक्षा शोधकर्ताओं ने PamStealer नामक एक नए macOS सूचना चोर की पहचान की है। यह मैलवेयर एक संकलित AppleScript (.scpt) फ़ाइल के रूप में वितरित किया जाता है जो Maccy, एक वैध ओपन-सोर्स क्लिपबोर्ड प्रबंधक, का रूप धारण करता है। यह सिस्टम को संक्रमित करने और लॉगिन पासवर्ड सहित संवेदनशील डेटा चुराने के लिए कई चतुर चालों का उपयोग करता है।

{{< ad-banner >}}

PamStealer का नाम macOS पर प्लगेबल ऑथेंटिकेशन मॉड्यूल (PAM) फ्रेमवर्क का दुरुपयोग करने की इसकी क्षमता से आया है। प्रमाणीकरण प्रक्रियाओं को इंटरसेप्ट करके, यह उपयोगकर्ता क्रेडेंशियल्स को कैप्चर कर सकता है जब वे लॉग इन करते हैं या विशेषाधिकार प्राप्त संचालन के लिए प्रमाणित होते हैं। फिर चोर चुराए गए डेटा को हमलावर-नियंत्रित सर्वरों पर बाहर निकालता है।

यह अभियान उपयोगकर्ताओं को दुर्भावनापूर्ण .scpt फ़ाइल डाउनलोड करने के लिए धोखा देने के लिए नकली वेबसाइटों और सोशल इंजीनियरिंग पर निर्भर करता है। एक बार निष्पादित होने के बाद, मैलवेयर संदेह पैदा किए बिना पासवर्ड हार्वेस्ट करने के लिए PAM जांच करता है। macOS एंडपॉइंट वाले संगठनों को असामान्य .scpt फ़ाइल निष्पादन और PAM-संबंधित विसंगतियों की निगरानी करनी चाहिए।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, यह macOS एंडपॉइंट पर संकलित AppleScript निष्पादन और PAM संशोधनों की निगरानी की आवश्यकता पर प्रकाश डालता है। DevSecOps टीमों को एप्लिकेशन व्हाइटलिस्टिंग लागू करनी चाहिए और उपयोगकर्ताओं को सॉफ़्टवेयर स्रोतों, विशेष रूप से क्लिपबोर्ड प्रबंधकों की पुष्टि करने के बारे में शिक्षित करना चाहिए। PAM दुरुपयोग के लिए एंडपॉइंट डिटेक्शन नियम लागू करने से इस चोर को जल्दी पकड़ने में मदद मिल सकती है।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html)**
