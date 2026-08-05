---
title: "TP-Link ने Omada ZTP की 15 खामियों को पैच किया जो RCE श्रृंखलाओं को सक्षम बनाती हैं"
date: "2026-08-05T09:37:58Z"
original_date: "2026-08-04T22:18:20"
lang: "hi"
translationKey: "tp-link-patches-15-omada-ztp-flaws-enabling-rce-chains"
slug: "tp-link-patches-15-omada-ztp-flaws-enabling-rce-chains"
author: "NewsBot (Validated by Federico Sella)"
description: "TP-Link ने Omada ज़ीरो-टच प्रोविज़निंग में 15 कमजोरियों को ठीक किया जो पिछले बग्स के साथ जोड़कर रिमोट कोड निष्पादन की अनुमति दे सकती हैं।"
original_url: "https://www.bleepingcomputer.com/news/security/tp-link-patches-omada-ztp-flaws-allowing-hackers-to-breach-networks/"
source: "BleepingComputer"
severity: "High"
target: "TP-Link Omada नेटवर्क डिवाइस"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

TP-Link ने Omada ज़ीरो-टच प्रोविज़निंग में 15 कमजोरियों को ठीक किया जो पिछले बग्स के साथ जोड़कर रिमोट कोड निष्पादन की अनुमति दे सकती हैं।

{{< cyber-report severity="High" source="BleepingComputer" target="TP-Link Omada नेटवर्क डिवाइस" >}}

TP-Link ने अपने Omada नेटवर्क डिवाइसों के ज़ीरो-टच प्रोविज़निंग (ZTP) तंत्र में 15 कमजोरियों को संबोधित करते हुए पैच जारी किए हैं। यदि इनका शोषण किया जाता है, तो ये खामियां हमलावरों को नेटवर्क इंफ्रास्ट्रक्चर से समझौता करने की अनुमति दे सकती हैं, जिससे एंटरप्राइज़ वातावरण में अनधिकृत पहुंच और पार्श्व गति हो सकती है।

{{< ad-banner >}}

ये कमजोरियां विशेष रूप से चिंताजनक हैं क्योंकि इन्हें पहले से खुलासा की गई खामियों के साथ जोड़कर रिमोट कोड निष्पादन (RCE) प्राप्त किया जा सकता है। इसका मतलब है कि एक हमलावर भौतिक पहुंच या वैध क्रेडेंशियल्स की आवश्यकता के बिना प्रभावित डिवाइसों पर पूर्ण नियंत्रण प्राप्त कर सकता है, जो नेटवर्क प्रबंधन के लिए Omada पर निर्भर संगठनों के लिए एक महत्वपूर्ण जोखिम पैदा करता है।

प्रशासकों को दृढ़ता से सलाह दी जाती है कि वे तुरंत नवीनतम फर्मवेयर अपडेट लागू करें। इसके अतिरिक्त, संभावित शोषण के प्रभाव को कम करने के लिए नेटवर्क विभाजन और एक्सेस नियंत्रणों की समीक्षा करने की सिफारिश की जाती है, विशेष रूप से उन वातावरणों में जहां ZTP सक्रिय रूप से उपयोग किया जाता है।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, Omada डिवाइसों को पैच करने को प्राथमिकता दें और असामान्य ZTP गतिविधि की निगरानी करें, क्योंकि इन खामियों का वास्तविक दुनिया में शोषण किया जा सकता है। DevSecOps टीमों को ZTP को उच्च जोखिम वाली हमले की सतह के रूप में मानना चाहिए और विस्फोट त्रिज्या को सीमित करने के लिए सख्त नेटवर्क विभाजन लागू करना चाहिए। श्रृंखलाबद्ध होने की क्षमता को देखते हुए, यदि कोई संदिग्ध ट्रैफ़िक देखा जाता है तो समझौता मान लें और गहन फोरेंसिक विश्लेषण करें।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/tp-link-patches-omada-ztp-flaws-allowing-hackers-to-breach-networks/)**
