---
title: "Mirai-व्युत्पन्न xlabs_v1 बॉटनेट DDoS के लिए ADB के माध्यम से IoT उपकरणों को हाईजैक करता है"
date: "2026-05-07T09:27:29Z"
original_date: "2026-05-06T20:21:00"
lang: "hi"
translationKey: "mirai-derived-xlabs-v1-botnet-hijacks-iot-devices-via-adb-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "शोधकर्ताओं ने xlabs_v1 का पता लगाया, जो एक नया Mirai-आधारित बॉटनेट है जो उजागर Android Debug Bridge पोर्ट का शोषण करके IoT उपकरणों को DDoS नेटवर्क में भर्ती करता है।"
original_url: "https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html"
source: "The Hacker News"
severity: "High"
target: "उजागर ADB वाले IoT उपकरण"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

शोधकर्ताओं ने xlabs_v1 का पता लगाया, जो एक नया Mirai-आधारित बॉटनेट है जो उजागर Android Debug Bridge पोर्ट का शोषण करके IoT उपकरणों को DDoS नेटवर्क में भर्ती करता है।

{{< cyber-report severity="High" source="The Hacker News" target="उजागर ADB वाले IoT उपकरण" >}}

साइबर सुरक्षा शोधकर्ताओं ने एक नए Mirai-व्युत्पन्न बॉटनेट की पहचान की है, जो स्वयं को xlabs_v1 के रूप में पहचानता है, जो Android Debug Bridge (ADB) चलाने वाले इंटरनेट-एक्सपोज़्ड उपकरणों को लक्षित करता है। बॉटनेट का उद्देश्य समझौता किए गए उपकरणों को एक नेटवर्क में शामिल करना है जो वितरित सेवा-अस्वीकरण (DDoS) हमले शुरू करने में सक्षम है।

{{< ad-banner >}}

यह खोज Hunt.io द्वारा की गई जब उन्होंने नीदरलैंड में होस्ट किए गए एक सर्वर पर एक उजागर निर्देशिका की पहचान की। मैलवेयर ADB का शोषण करता है, जो Android उपकरणों को डीबग करने के लिए उपयोग किया जाने वाला एक कमांड-लाइन टूल है, जो अक्सर IoT उपकरणों पर खुला छोड़ दिया जाता है, जिससे दूरस्थ हमलावरों को अनधिकृत पहुंच प्राप्त होती है।

यह अभियान खराब सुरक्षित IoT उपकरणों को लक्षित करने वाले Mirai वेरिएंट के चल रहे खतरे को उजागर करता है। संगठनों को सलाह दी जाती है कि वे उत्पादन उपकरणों पर ADB को अक्षम करें और इस तरह के अपहरण को रोकने के लिए नेटवर्क पहुंच को प्रतिबंधित करें।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, बाहरी IP से अप्रत्याशित ADB कनेक्शन की निगरानी करें। DevSecOps टीमों को सुनिश्चित करना चाहिए कि उत्पादन बिल्ड में ADB अक्षम हो और इस बॉटनेट की पहुंच को कम करने के लिए IoT उपकरणों को महत्वपूर्ण नेटवर्क से अलग किया जाए।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html)**
