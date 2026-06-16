---
title: "DragonForce रैनसमवेयर C2 ट्रैफिक छिपाने के लिए Microsoft Teams रिले का उपयोग करता है"
date: "2026-06-16T12:10:12Z"
original_date: "2026-06-16T10:18:48"
lang: "hi"
translationKey: "dragonforce-ransomware-uses-microsoft-teams-relays-to-hide-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "DragonForce रैनसमवेयर Microsoft Teams रिले इंफ्रास्ट्रक्चर के भीतर कमांड-एंड-कंट्रोल ट्रैफिक को छिपाने के लिए कस्टम मैलवेयर 'Backdoor.Turn' तैनात करता है।"
original_url: "https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/"
source: "BleepingComputer"
severity: "High"
target: "Microsoft Teams रिले इंफ्रास्ट्रक्चर"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

DragonForce रैनसमवेयर Microsoft Teams रिले इंफ्रास्ट्रक्चर के भीतर कमांड-एंड-कंट्रोल ट्रैफिक को छिपाने के लिए कस्टम मैलवेयर 'Backdoor.Turn' तैनात करता है।

{{< cyber-report severity="High" source="BleepingComputer" target="Microsoft Teams रिले इंफ्रास्ट्रक्चर" >}}

DragonForce रैनसमवेयर समूह को Microsoft Teams रिले इंफ्रास्ट्रक्चर के भीतर अपने कमांड-एंड-कंट्रोल (C2) ट्रैफिक को छिपाने के लिए 'Backdoor.Turn' नामक कस्टम मैलवेयर का उपयोग करते हुए देखा गया है। यह तकनीक हमलावरों को दुर्भावनापूर्ण संचार को वैध Teams ट्रैफिक के साथ मिश्रित करने की अनुमति देती है, जिससे नेटवर्क रक्षकों के लिए पहचान करना अधिक कठिन हो जाता है।

{{< ad-banner >}}

Microsoft Teams रिले का दुरुपयोग करके, रैनसमवेयर गिरोह पारंपरिक नेटवर्क सुरक्षा नियंत्रणों को बायपास कर सकता है जो विश्वसनीय सेवाओं के ट्रैफिक की जांच नहीं कर सकते हैं। मैलवेयर संभवतः C2 डेटा को टनल करने के लिए Teams API या प्रोटोकॉल का लाभ उठाता है, सिग्नेचर-आधारित डिटेक्शन से बचता है और समझौता किए गए नेटवर्कों में लगातार पहुंच की अनुमति देता है।

Microsoft Teams का उपयोग करने वाले संगठनों को Teams एंडपॉइंट्स पर असामान्य आउटबाउंड ट्रैफिक पैटर्न की निगरानी करनी चाहिए और एन्क्रिप्टेड टनल के लिए अतिरिक्त निरीक्षण लागू करने पर विचार करना चाहिए। यह घटना रैनसमवेयर समूहों द्वारा पहचान से बचने के लिए लिविंग-ऑफ-द-लैंड और विश्वसनीय सेवा दुरुपयोग तकनीकों को अपनाने की बढ़ती प्रवृत्ति को उजागर करती है।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, यह सामान्य Teams ट्रैफिक को बेसलाइन करने और डेटा वॉल्यूम में अप्रत्याशित वृद्धि या गैर-मानक Teams एंडपॉइंट्स से कनेक्शन जैसी विसंगतियों पर अलर्ट करने की आवश्यकता को रेखांकित करता है। DevSecOps टीमों को Teams एकीकरण अनुमतियों की समीक्षा करनी चाहिए और रिले दुरुपयोग के लिए हमले की सतह को कम करने के लिए अनावश्यक API एक्सेस को प्रतिबंधित करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)**
