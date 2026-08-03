---
title: "JetBrains ने TeamCity में गंभीर प्रमाणीकरण बाईपास की चेतावनी दी जिससे RCE हो सकता है"
date: "2026-08-03T10:38:49Z"
original_date: "2026-07-30T22:01:31"
lang: "hi"
translationKey: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
slug: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "JetBrains ने TeamCity On-Premises में एक गंभीर प्रमाणीकरण बाईपास की चेतावनी दी है जो रिमोट कोड निष्पादन की अनुमति दे सकता है। तुरंत पैच लगाने की सलाह दी गई है।"
original_url: "https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/"
source: "BleepingComputer"
severity: "Critical"
target: "TeamCity On-Premises"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

JetBrains ने TeamCity On-Premises में एक गंभीर प्रमाणीकरण बाईपास की चेतावनी दी है जो रिमोट कोड निष्पादन की अनुमति दे सकता है। तुरंत पैच लगाने की सलाह दी गई है।

{{< cyber-report severity="Critical" source="BleepingComputer" target="TeamCity On-Premises" >}}

JetBrains ने TeamCity On-Premises को प्रभावित करने वाली एक गंभीर प्रमाणीकरण बाईपास भेद्यता के बारे में चेतावनी जारी की है। इस दोष का फायदा एक अनधिकृत हमलावर प्रभावित सर्वर पर रिमोट कोड निष्पादन प्राप्त करने के लिए उठा सकता है, जो TeamCity पर अपने बिल्ड और सतत एकीकरण पाइपलाइनों के लिए निर्भर संगठनों के लिए गंभीर जोखिम पैदा करता है।

{{< ad-banner >}}

यह भेद्यता विशेष रूप से चिंताजनक है क्योंकि TeamCity सर्वर अक्सर संवेदनशील स्रोत कोड, बिल्ड आर्टिफैक्ट और क्रेडेंशियल रखते हैं, जिससे वे हमलावरों के लिए उच्च-मूल्य वाले लक्ष्य बन जाते हैं। सफल शोषण से सर्वर से पूरी तरह समझौता हो सकता है और यदि सर्वर को ठीक से अलग नहीं किया गया है तो संभावित रूप से व्यापक बुनियादी ढांचे से समझौता हो सकता है।

TeamCity On-Premises का उपयोग करने वाले संगठनों को विक्रेता द्वारा प्रदान किए गए सुरक्षा अपडेट को तुरंत लागू करने को प्राथमिकता देनी चाहिए। पैच लागू होने तक, TeamCity सर्वर तक नेटवर्क पहुंच को प्रतिबंधित करने और किसी भी संदिग्ध गतिविधि की निगरानी करने की सिफारिश की जाती है।

{{< netrunner-insight >}}

यह एक गंभीर भेद्यता है जिसे आपातकाल के रूप में माना जाना चाहिए। SOC विश्लेषकों को तुरंत जांचना चाहिए कि क्या उनका संगठन TeamCity On-Premises का उपयोग करता है और पैच स्थिति सत्यापित करें। अनधिकृत RCE की संभावना को देखते हुए, यदि सर्वर उजागर है तो समझौता मान लें और पूरी तरह से फोरेंसिक समीक्षा करें। DevSecOps टीमों को भी बिल्ड सर्वर को विभाजित करने और विस्फोट त्रिज्या को कम करने के लिए सख्त पहुंच नियंत्रण लागू करने पर विचार करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/)**
