---
title: "Mandiant ने Cisco SD-WAN जीरो-डे रूट एक्सेस हमलों का खुलासा किया"
date: "2026-06-25T10:15:15Z"
original_date: "2026-06-24T21:29:10"
lang: "hi"
translationKey: "mandiant-exposes-cisco-sd-wan-zero-day-root-access-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "नए विवरण बताते हैं कि कैसे हैकर्स ने Cisco Catalyst SD-WAN उपकरणों पर नकली रूट खाते बनाने के लिए CVE-2026-20245 का जीरो-डे हमलों में शोषण किया।"
original_url: "https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/"
source: "BleepingComputer"
severity: "High"
target: "Cisco Catalyst SD-WAN उपकरण"
cve: "CVE-2026-20245"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

नए विवरण बताते हैं कि कैसे हैकर्स ने Cisco Catalyst SD-WAN उपकरणों पर नकली रूट खाते बनाने के लिए CVE-2026-20245 का जीरो-डे हमलों में शोषण किया।

{{< cyber-report severity="High" source="BleepingComputer" target="Cisco Catalyst SD-WAN उपकरण" cve="CVE-2026-20245" >}}

Mandiant ने खुलासा किया है कि कैसे खतरे वाले अभिनेताओं ने Cisco Catalyst SD-WAN सॉफ्टवेयर में CVE-2026-20245 के रूप में ट्रैक की गई जीरो-डे कमजोरी का शोषण करके लक्षित उपकरणों पर रूट एक्सेस प्राप्त किया। हमलों में नकली रूट खाते बनाना शामिल था, जिससे लगातार अनधिकृत पहुंच संभव हो सकी।

{{< ad-banner >}}

यह कमजोरी, जिसे Cisco ने हाल ही में एक सलाह में पैच किया था, सीमित, लक्षित हमलों में उपयोग की गई। Mandiant के विश्लेषण से विशिष्ट शोषण श्रृंखला का पता चलता है, जो सुरक्षा अपडेट को तुरंत लागू करने के महत्व पर जोर देती है।

Cisco SD-WAN समाधानों का उपयोग करने वाले संगठनों से अनधिकृत खातों या असामान्य रूट-स्तरीय गतिविधि जैसे समझौते के संकेतों के लिए अपने सिस्टम का ऑडिट करने का आग्रह किया जाता है। यह घटना मजबूत पैच प्रबंधन और नेटवर्क बुनियादी ढांचे की निगरानी की महत्वपूर्ण आवश्यकता को रेखांकित करती है।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, Cisco SD-WAN उपकरणों पर अनधिकृत खाता निर्माण और विशेषाधिकार वृद्धि घटनाओं की निगरानी को प्राथमिकता दें। DevSecOps टीमों को Cisco के सुरक्षा पैच के तेजी से तैनाती सुनिश्चित करनी चाहिए और हमले की सतह को कम करने के लिए SD-WAN प्रबंधन इंटरफेस को विभाजित करने पर विचार करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/)**
