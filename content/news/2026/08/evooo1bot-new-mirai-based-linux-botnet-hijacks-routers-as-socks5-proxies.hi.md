---
title: "Evooo1Bot: नया Mirai-आधारित Linux बॉटनेट राउटरों को SOCKS5 प्रॉक्सी के रूप में हाईजैक करता है"
date: "2026-08-16T07:24:07Z"
original_date: "2026-08-15T14:14:38"
lang: "hi"
translationKey: "evooo1bot-new-mirai-based-linux-botnet-hijacks-routers-as-socks5-proxies"
slug: "evooo1bot-new-mirai-based-linux-botnet-hijacks-routers-as-socks5-proxies"
author: "NewsBot (Validated by Federico Sella)"
description: "Evooo1Bot, एक मॉड्यूलर Mirai वेरिएंट, इंटरनेट-फेसिंग गेटवे को लक्षित करता है, राउटरों को गुप्त ट्रैफिक के लिए SOCKS5 रिले नोड में बदल देता है।"
original_url: "https://www.bleepingcomputer.com/news/security/new-evooo1bot-linux-botnet-turns-routers-into-traffic-relay-nodes/"
source: "BleepingComputer"
severity: "High"
target: "इंटरनेट-फेसिंग गेटवे डिवाइस"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Evooo1Bot, एक मॉड्यूलर Mirai वेरिएंट, इंटरनेट-फेसिंग गेटवे को लक्षित करता है, राउटरों को गुप्त ट्रैफिक के लिए SOCKS5 रिले नोड में बदल देता है।

{{< cyber-report severity="High" source="BleepingComputer" target="इंटरनेट-फेसिंग गेटवे डिवाइस" >}}

Evooo1Bot नामक एक नया Mirai-आधारित Linux बॉटनेट इंटरनेट-फेसिंग गेटवे डिवाइसों, जैसे राउटर और अन्य नेटवर्क उपकरणों को लक्षित करते हुए देखा गया है। यह मैलवेयर डिज़ाइन में मॉड्यूलर है, जिससे प्रारंभिक समझौते के बाद इसे नई कार्यक्षमताओं के साथ अपडेट किया जा सकता है।

{{< ad-banner >}}

एक बार संक्रमित होने के बाद, समझौता किए गए डिवाइसों को SOCKS5 ट्रैफिक रिले नोड के रूप में पुनः उपयोग किया जाता है। यह बॉटनेट ऑपरेटरों को हाईजैक किए गए राउटरों के वितरित नेटवर्क के माध्यम से दुर्भावनापूर्ण ट्रैफिक को रूट करने में सक्षम बनाता है, जिससे हमलों की उत्पत्ति अस्पष्ट हो जाती है और संभावित रूप से नेटवर्क-आधारित सुरक्षा को दरकिनार किया जा सकता है।

SOCKS5 रिले का उपयोग विशिष्ट Mirai DDoS कार्यक्षमता से एक उल्लेखनीय विकास है, जो स्टील्थियर, प्रॉक्सी-आधारित संचालन की ओर बदलाव का संकेत देता है। संगठनों को यह सुनिश्चित करना चाहिए कि गेटवे डिवाइस पैच किए गए हैं, डिफ़ॉल्ट क्रेडेंशियल बदले गए हैं, और रिमोट मैनेजमेंट इंटरफेस इंटरनेट के संपर्क में नहीं हैं।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, यह नेटवर्क डिवाइसों से असामान्य आउटबाउंड कनेक्शन की निगरानी के महत्व को उजागर करता है, क्योंकि SOCKS5 रिले का उपयोग दुर्भावनापूर्ण ट्रैफिक को टनल करने के लिए किया जा सकता है। DevSecOps टीमों को अप्रयुक्त सेवाओं को अक्षम करके, मजबूत प्रमाणीकरण लागू करके और प्रबंधन इंटरफेस को अलग करके गेटवे डिवाइसों को सख्त करना चाहिए। Mirai वेरिएंट के लिए सक्रिय खतरे की खोज आवश्यक है, क्योंकि वे सरल DDoS टूल से आगे विकसित होते रहते हैं।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/new-evooo1bot-linux-botnet-turns-routers-into-traffic-relay-nodes/)**
