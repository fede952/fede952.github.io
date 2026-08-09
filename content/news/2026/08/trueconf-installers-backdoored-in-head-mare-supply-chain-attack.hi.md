---
title: "TrueConf इंस्टॉलर हैक किए गए: Head Mare सप्लाई-चेन हमला"
date: "2026-08-09T07:48:35Z"
original_date: "2026-08-08T14:16:23"
lang: "hi"
translationKey: "trueconf-installers-backdoored-in-head-mare-supply-chain-attack"
slug: "trueconf-installers-backdoored-in-head-mare-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Head Mare बिना पैच वाले TrueConf सर्वरों का फायदा उठाकर क्लाइंट इंस्टॉलर को बैकडोर वाले संस्करणों से बदल देता है, जिससे पीड़ितों तक मैलवेयर पहुंचता है।"
original_url: "https://www.bleepingcomputer.com/news/security/hackers-breach-trueconf-to-trojanize-client-installers-with-backdoors/"
source: "BleepingComputer"
severity: "High"
target: "TrueConf वीडियो कॉन्फ्रेंसिंग सर्वर"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Head Mare बिना पैच वाले TrueConf सर्वरों का फायदा उठाकर क्लाइंट इंस्टॉलर को बैकडोर वाले संस्करणों से बदल देता है, जिससे पीड़ितों तक मैलवेयर पहुंचता है।

{{< cyber-report severity="High" source="BleepingComputer" target="TrueConf वीडियो कॉन्फ्रेंसिंग सर्वर" >}}

हैक्टिविस्ट समूह Head Mare बिना पैच वाले TrueConf वीडियो कॉन्फ्रेंसिंग सर्वरों में सक्रिय रूप से कमजोरियों का फायदा उठा रहा है। इन सर्वरों से समझौता करके, हमलावर वैध क्लाइंट इंस्टॉलर को दुर्भावनापूर्ण संस्करणों से बदलने में सक्षम होते हैं जिनमें बैकडोर होते हैं।

{{< ad-banner >}}

जब उपयोगकर्ता ट्रोजनाइज़्ड इंस्टॉलर डाउनलोड और निष्पादित करते हैं, तो बैकडोर उनके सिस्टम पर तैनात हो जाते हैं, जिससे हमलावरों को संभावित रूप से दूरस्थ पहुंच और नियंत्रण मिल जाता है। यह सप्लाई-चेन शैली का हमला उस भरोसे का लाभ उठाता है जो उपयोगकर्ता आधिकारिक सॉफ्टवेयर वितरण चैनलों पर रखते हैं।

TrueConf का उपयोग करने वाले संगठनों को तुरंत अपने इंस्टॉलर की अखंडता सत्यापित करनी चाहिए और सुनिश्चित करना चाहिए कि सभी सर्वर ज्ञात कमजोरियों के खिलाफ पैच किए गए हैं। यह हमला सॉफ्टवेयर वितरण में असामान्य व्यवहार की निगरानी और मजबूत पैच प्रबंधन प्रथाओं को बनाए रखने के महत्व को उजागर करता है।

{{< netrunner-insight >}}

यह घटना सप्लाई-चेन सतर्कता की आवश्यकता को रेखांकित करती है: आधिकारिक स्रोतों से भी डाउनलोड किए गए इंस्टॉलर के चेकसम और हस्ताक्षर हमेशा सत्यापित करें। SOC टीमों के लिए, इंस्टॉलेशन के बाद असामान्य नेटवर्क कनेक्शन या प्रक्रियाओं की निगरानी करें जो बैकडोर सक्रियण का संकेत दे सकते हैं। पैच प्रबंधन महत्वपूर्ण है—बिना पैच वाले सर्वर हमलावरों के लिए आसान लक्ष्य होते हैं।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/hackers-breach-trueconf-to-trojanize-client-installers-with-backdoors/)**
