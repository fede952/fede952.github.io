---
title: "विंडोज BitLocker जीरो-डे बाईपास PoC जारी: YellowKey और GreenPlasma"
date: "2026-05-14T09:30:15Z"
original_date: "2026-05-13T16:37:49"
lang: "hi"
translationKey: "windows-bitlocker-zero-day-bypass-poc-released-yellowkey-and-greenplasma"
author: "NewsBot (Validated by Federico Sella)"
description: "दो अनपैच विंडोज कमजोरियों—YellowKey (BitLocker बाईपास) और GreenPlasma (विशेषाधिकार वृद्धि)—के प्रूफ-ऑफ-कॉन्सेप्ट एक्सप्लॉइट प्रकाशित किए गए हैं, जो एन्क्रिप्टेड ड्राइव्स के लिए जोखिम पैदा करते हैं।"
original_url: "https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/"
source: "BleepingComputer"
severity: "High"
target: "विंडोज BitLocker संरक्षित ड्राइव्स"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

दो अनपैच विंडोज कमजोरियों—YellowKey (BitLocker बाईपास) और GreenPlasma (विशेषाधिकार वृद्धि)—के प्रूफ-ऑफ-कॉन्सेप्ट एक्सप्लॉइट प्रकाशित किए गए हैं, जो एन्क्रिप्टेड ड्राइव्स के लिए जोखिम पैदा करते हैं।

{{< cyber-report severity="High" source="BleepingComputer" target="विंडोज BitLocker संरक्षित ड्राइव्स" >}}

एक साइबर सुरक्षा शोधकर्ता ने दो अनपैच माइक्रोसॉफ्ट विंडोज कमजोरियों, जिन्हें YellowKey और GreenPlasma नाम दिया गया है, के लिए प्रूफ-ऑफ-कॉन्सेप्ट (PoC) एक्सप्लॉइट जारी किए हैं। YellowKey एक BitLocker बाईपास है जो हमलावरों को उचित प्रमाणीकरण के बिना संरक्षित ड्राइव्स पर डेटा तक पहुंचने की अनुमति देता है, जबकि GreenPlasma एक विशेषाधिकार-वृद्धि दोष है जो हमलावर को एक समझौता प्रणाली पर उन्नत अनुमतियां प्राप्त करने में सक्षम बना सकता है।

{{< ad-banner >}}

इन PoCs के प्रकाशन से शोषण का जोखिम बढ़ जाता है, क्योंकि खतरे के अभिनेता अब तकनीकों को हथियार बना सकते हैं। पूर्ण-डिस्क एन्क्रिप्शन के लिए BitLocker पर निर्भर संगठनों को अपने जोखिम का आकलन करना चाहिए और अतिरिक्त सुरक्षा नियंत्रणों पर विचार करना चाहिए, जैसे TPM+PIN सुरक्षा सक्षम करना या प्री-बूट प्रमाणीकरण का उपयोग करना।

माइक्रोसॉफ्ट ने अभी तक इन कमजोरियों के लिए पैच जारी नहीं किए हैं, जिससे सिस्टम फिक्स तैनात होने तक उजागर रहते हैं। सुरक्षा टीमों को एन्क्रिप्टेड ड्राइव्स तक असामान्य पहुंच पैटर्न की निगरानी करनी चाहिए और जहां संभव हो, वर्कअराउंड लागू करना चाहिए, जैसे अनावश्यक बूट विकल्पों को अक्षम करना या मजबूत PIN नीतियों को लागू करना।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, BitLocker-संरक्षित ड्राइव्स तक अनधिकृत पहुंच के प्रयासों और विशेषाधिकार वृद्धि घटनाओं की निगरानी को प्राथमिकता दें। DevSecOps इंजीनियरों को प्रकाशित PoCs के विरुद्ध अपने वातावरण का परीक्षण करना चाहिए ताकि कमजोर कॉन्फ़िगरेशन की पहचान हो सके और Secure Boot और मापा बूट लॉग जैसे प्रतिपूरक नियंत्रण लागू किए जा सकें।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)**
