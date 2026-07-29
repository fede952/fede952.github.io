---
title: "समझौता किए गए joyfill npm पैकेज Node.js प्रोजेक्ट्स में RAT पहुंचाते हैं"
date: "2026-07-29T09:34:53Z"
original_date: "2026-07-29T04:20:57"
lang: "hi"
translationKey: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
slug: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
author: "NewsBot (Validated by Federico Sella)"
description: "@joyfill/layouts और @joyfill/components के बीटा संस्करणों में एक इम्पोर्ट-टाइम जावास्क्रिप्ट इम्प्लांट है जो एन्क्रिप्टेड कोड को हल करके एक रिमोट एक्सेस ट्रोजन तैनात करता है।"
original_url: "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "joyfill पैकेज का उपयोग करने वाले Node.js डेवलपर्स"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

@joyfill/layouts और @joyfill/components के बीटा संस्करणों में एक इम्पोर्ट-टाइम जावास्क्रिप्ट इम्प्लांट है जो एन्क्रिप्टेड कोड को हल करके एक रिमोट एक्सेस ट्रोजन तैनात करता है।

{{< cyber-report severity="High" source="The Hacker News" target="joyfill पैकेज का उपयोग करने वाले Node.js डेवलपर्स" >}}

@joyfill नेमस्पेस में दो npm पैकेज, @joyfill/layouts संस्करण 0.1.2-2773.beta.0 और @joyfill/components संस्करण 4.0.0-rc24-2773-beta.4, से समझौता किया गया है। इन बीटा रिलीज़ में एक इम्पोर्ट-टाइम जावास्क्रिप्ट इम्प्लांट है जो एन्क्रिप्टेड कोड को हल करता है, अंततः DEV#POPPER मैलवेयर परिवार से जुड़ा एक रिमोट एक्सेस ट्रोजन (RAT) वितरित करता है।

{{< ad-banner >}}

दुर्भावनापूर्ण कोड तब निष्पादित होता है जब पैकेज को Node.js प्रोजेक्ट में आयात किया जाता है, जिससे हमलावरों को समझौता किए गए सिस्टम तक रिमोट एक्सेस मिल जाता है। यह हमला npm इकोसिस्टम को लक्षित करने वाले सप्लाई चेन हमलों के चल रहे जोखिम को उजागर करता है, विशेष रूप से बीटा या रिलीज़ कैंडिडेट संस्करणों के माध्यम से जिनकी कम जांच हो सकती है।

जिन डेवलपर्स ने इन विशिष्ट संस्करणों का उपयोग किया है, उन्हें तुरंत क्रेडेंशियल्स बदलने चाहिए, समझौते के संकेतकों के लिए स्कैन करना चाहिए, और किसी भी अन्य संदिग्ध पैकेज के लिए अपने डिपेंडेंसी ट्री की समीक्षा करनी चाहिए। npm रजिस्ट्री ने संभवतः दुर्भावनापूर्ण संस्करणों को हटा दिया है, लेकिन मौजूदा इंस्टॉलेशन खतरा बने हुए हैं।

{{< netrunner-insight >}}

यह घटना प्री-रिलीज़ पैकेजों की जांच और डिपेंडेंसी इंटीग्रिटी जांच को लागू करने के महत्व को रेखांकित करती है। SOC विश्लेषकों को Node.js एप्लिकेशन से असामान्य आउटबाउंड कनेक्शन की निगरानी करनी चाहिए, जबकि DevSecOps टीमों को सख्त वर्जन पिनिंग लागू करनी चाहिए और ज्ञात दुर्भावनापूर्ण पैकेजों का पता लगाने के लिए npm audit या SCA स्कैनर जैसे टूल का उपयोग करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html)**
