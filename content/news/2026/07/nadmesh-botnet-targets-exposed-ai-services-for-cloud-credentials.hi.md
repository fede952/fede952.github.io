---
title: "NadMesh बॉटनेट क्लाउड क्रेडेंशियल्स के लिए खुले AI सेवाओं को निशाना बनाता है"
date: "2026-07-19T09:05:56Z"
original_date: "2026-07-17T17:12:23"
lang: "hi"
translationKey: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
slug: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "एक नया Go-आधारित बॉटनेट, NadMesh, ComfyUI और Ollama जैसे खुले AI प्लेटफार्मों की खोज करता है, AWS कुंजियाँ और Kubernetes टोकन चुराता है। 3,800 से अधिक कुंजियाँ चुराए जाने का दावा।"
original_url: "https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html"
source: "The Hacker News"
severity: "High"
target: "खुले AI सेवाएँ (ComfyUI, Ollama, n8n, आदि)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

एक नया Go-आधारित बॉटनेट, NadMesh, ComfyUI और Ollama जैसे खुले AI प्लेटफार्मों की खोज करता है, AWS कुंजियाँ और Kubernetes टोकन चुराता है। 3,800 से अधिक कुंजियाँ चुराए जाने का दावा।

{{< cyber-report severity="High" source="The Hacker News" target="खुले AI सेवाएँ (ComfyUI, Ollama, n8n, आदि)" >}}

NadMesh नामक एक नया बॉटनेट, जो Go में लिखा गया है, जुलाई 2026 की शुरुआत में उभरा, जो क्लाउड क्रेडेंशियल्स और Kubernetes टोकन चुराने के लिए खुले AI सेवाओं को निशाना बनाता है। बॉटनेट के ऑपरेटर डैशबोर्ड में कथित तौर पर 3,811 अद्वितीय AWS कुंजियाँ एकत्रित दिखाई गई हैं, जो एक महत्वपूर्ण परिचालन पैमाने का संकेत देती हैं। NadMesh एक Shodan-आधारित हार्वेस्टर का उपयोग करता है जो लगातार अपनी स्कैन कतार को ComfyUI, Ollama, n8n, Open WebUI, Langflow, और Gradio जैसे लोकप्रिय AI उपकरणों के कमजोर उदाहरणों से भरता है।

{{< ad-banner >}}

ये AI प्लेटफॉर्म अक्सर विकास टीमों द्वारा उचित सुरक्षा सख्ती के बिना तेजी से तैनात किए जाते हैं, जिससे वे इंटरनेट के लिए खुले रह जाते हैं। बॉटनेट फायरवॉल सुरक्षा की इस कमी का फायदा उठाकर पहुँच प्राप्त करता है और संवेदनशील क्रेडेंशियल्स निकालता है। AI सेवाओं पर ध्यान केंद्रित करना उच्च-मूल्य वाले क्लाउड बुनियादी ढाँचे और मशीन लर्निंग पाइपलाइनों की ओर हमलावरों के लक्ष्यीकरण में बदलाव का सुझाव देता है।

इन AI उपकरणों को चलाने वाले संगठनों को तुरंत अपने एक्सपोज़र का ऑडिट करना चाहिए, नेटवर्क पहुँच को प्रतिबंधित करना चाहिए, और किसी भी क्रेडेंशियल को बदलना चाहिए जो समझौता हो सकता है। NadMesh बॉटनेट बढ़ते खतरे के परिदृश्य को प्रदर्शित करता है जहाँ गलत कॉन्फ़िगर की गई AI सेवाएँ क्रेडेंशियल चोरी और पार्श्व आंदोलन के लिए प्रमुख लक्ष्य बन जाती हैं।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए: अपने वातावरण में खुले ComfyUI, Ollama और समान AI सेवाओं की स्कैनिंग को प्राथमिकता दें। DevSecOps टीमों को इन उपकरणों को तैनात करने से पहले नेटवर्क सेगमेंटेशन और फायरवॉल नियमों को लागू करना चाहिए। NadMesh बॉटनेट एक स्पष्ट अनुस्मारक है कि सुरक्षा समीक्षा के बिना तेजी से तैनाती स्वचालित क्रेडेंशियल हार्वेस्टिंग को आमंत्रित करती है।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html)**
