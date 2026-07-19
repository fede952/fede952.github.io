---
title: "HollowByte DDoS दोष OpenSSL सर्वर की मेमोरी को 11-बाइट पेलोड से फुलाता है"
date: "2026-07-19T09:04:58Z"
original_date: "2026-07-17T17:56:21"
lang: "hi"
translationKey: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
slug: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
author: "NewsBot (Validated by Federico Sella)"
description: "HollowByte नामक एक कमजोरी अनधिकृत हमलावरों को केवल 11 बाइट्स के दुर्भावनापूर्ण पेलोड के साथ OpenSSL सर्वर पर सेवा-अस्वीकृति की स्थिति उत्पन्न करने की अनुमति देती है।"
original_url: "https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/"
source: "BleepingComputer"
severity: "High"
target: "OpenSSL सर्वर"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

HollowByte नामक एक कमजोरी अनधिकृत हमलावरों को केवल 11 बाइट्स के दुर्भावनापूर्ण पेलोड के साथ OpenSSL सर्वर पर सेवा-अस्वीकृति की स्थिति उत्पन्न करने की अनुमति देती है।

{{< cyber-report severity="High" source="BleepingComputer" target="OpenSSL सर्वर" >}}

HollowByte नामक एक नई खोजी गई कमजोरी अनधिकृत हमलावरों को केवल 11 बाइट्स के विशेष रूप से तैयार पेलोड भेजकर OpenSSL सर्वर पर सेवा-अस्वीकृति (DoS) की स्थिति उत्पन्न करने में सक्षम बनाती है। यह दोष मेमोरी आवंटन अक्षमताओं का शोषण करता है, जिससे सर्वर की मेमोरी फूल जाती है और अंततः उपलब्ध संसाधन समाप्त हो जाते हैं।

{{< ad-banner >}}

हमले के लिए प्रमाणीकरण की आवश्यकता नहीं है और इसे दूरस्थ रूप से निष्पादित किया जा सकता है, जो सुरक्षित संचार के लिए OpenSSL पर निर्भर किसी भी संगठन के लिए एक महत्वपूर्ण खतरा है। न्यूनतम पेलोड आकार हमलावरों को सीमित बैंडविड्थ के साथ अपने प्रभाव को बढ़ाने की अनुमति देता है, संभावित रूप से न्यूनतम प्रयास में सर्वर को अभिभूत कर सकता है।

हालांकि अभी तक कोई CVE पहचानकर्ता निर्दिष्ट नहीं किया गया है, कमजोरी को OpenSSL परियोजना को सूचित किया गया है, और पैच की उम्मीद है। इस बीच, प्रशासकों को मेमोरी उपयोग की निगरानी करने और संभावित शोषण को कम करने के लिए दर सीमित या घुसपैठ का पता लगाने के नियम लागू करने की सलाह दी जाती है।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, यह एक क्लासिक कम-बैंडविड्थ, उच्च-प्रभाव DoS वेक्टर है जो पारंपरिक वॉल्यूमेट्रिक रक्षा को बायपास कर सकता है। DevSecOps टीमों को उपलब्ध होने पर पैचिंग को प्राथमिकता देनी चाहिए और असामान्य वृद्धि का पता लगाने के लिए मेमोरी मॉनिटरिंग अलर्ट तैनात करने पर विचार करना चाहिए। 11-बाइट पेलोड इसे खतरे का पता लगाने के नियमों में शामिल करने के लिए एक आदर्श उम्मीदवार बनाता है।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/)**
