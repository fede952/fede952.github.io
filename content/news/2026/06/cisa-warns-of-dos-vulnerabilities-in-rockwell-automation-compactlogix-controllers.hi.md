---
title: "CISA ने Rockwell Automation CompactLogix नियंत्रकों में DoS कमजोरियों की चेतावनी दी"
date: "2026-06-17T11:46:16Z"
original_date: "2026-06-16T12:00:00"
lang: "hi"
translationKey: "cisa-warns-of-dos-vulnerabilities-in-rockwell-automation-compactlogix-controllers"
author: "NewsBot (Validated by Federico Sella)"
description: "Rockwell Automation CompactLogix 5370 नियंत्रकों में कई कमजोरियाँ सेवा-अस्वीकार हमलों की अनुमति दे सकती हैं। CVE-2025-11694 इन दोषों में से एक है।"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04"
source: "CISA"
severity: "High"
target: "Rockwell Automation CompactLogix 5370 नियंत्रक"
cve: "CVE-2025-11694"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Rockwell Automation CompactLogix 5370 नियंत्रकों में कई कमजोरियाँ सेवा-अस्वीकार हमलों की अनुमति दे सकती हैं। CVE-2025-11694 इन दोषों में से एक है।

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation CompactLogix 5370 नियंत्रक" cve="CVE-2025-11694" cvss="7.5" >}}

CISA ने एक सलाह (ICSA-26-167-04) जारी की है जिसमें Rockwell Automation CompactLogix 5370 नियंत्रकों (L1, L2, L3) में कमजोरियों का विवरण दिया गया है। दोषों में अखंडता जाँच मानों का अनुचित सत्यापन और संवेदनशील सिस्टम जानकारी का खुलासा शामिल है, जो एक हमलावर को सेवा-अस्वीकार की स्थिति उत्पन्न करने की अनुमति दे सकता है। यह सलाह V38.011 से पहले के संस्करणों को प्रभावित करती है।

{{< ad-banner >}}

सबसे उल्लेखनीय कमजोरी, CVE-2025-11694, में CIP प्रोटोकॉल में अनुक्रम संख्याओं और स्रोत IP पतों का सत्यापन न होना शामिल है। एक हमलावर वेब इंटरफ़ेस पर दिखाई देने वाले उजागर कनेक्शन आईडी का उपयोग करके सेवा-अस्वीकार हमले कर सकता है, जिसके परिणामस्वरूप एक मामूली दोष उत्पन्न होता है। इस कमजोरी के लिए CVSS v3 स्कोर 7.5 है।

Rockwell Automation इन मुद्दों को हल करने के लिए संस्करण V38.011 में अपडेट करने की सिफारिश करता है। प्रभावित उत्पाद दुनिया भर में क्रिटिकल मैन्युफैक्चरिंग क्षेत्र में तैनात हैं। संगठनों को संभावित परिचालन व्यवधानों को कम करने के लिए इन नियंत्रकों को पैच करने को प्राथमिकता देनी चाहिए।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, CompactLogix नियंत्रकों को लक्षित करने वाले असामान्य CIP ट्रैफ़िक पैटर्न या बार-बार कनेक्शन प्रयासों की निगरानी करें। DevSecOps इंजीनियरों को यह सुनिश्चित करना चाहिए कि वेब इंटरफ़ेस अविश्वसनीय नेटवर्कों के लिए उजागर न हो और तुरंत फर्मवेयर अपडेट V38.011 लागू करें। यह एक सीधा DoS वेक्टर है जिसे उचित नेटवर्क विभाजन और पैच प्रबंधन से कम किया जा सकता है।

{{< /netrunner-insight >}}

---

**[पूरा लेख CISA पर पढ़ें ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04)**
