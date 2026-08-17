---
title: "PyPI पर दुर्भावनापूर्ण LiteLLM रिलीज़, Trivy हैक से जुड़ी, 2,100+ संगठनों को उजागर करती हैं"
date: "2026-08-17T07:48:06Z"
original_date: "2026-08-12T08:04:52"
lang: "hi"
translationKey: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
slug: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
author: "NewsBot (Validated by Federico Sella)"
description: "PyPI पर दो दुर्भावनापूर्ण LiteLLM पैकेजों ने क्लाउड कुंजियाँ, SSH कुंजियाँ और बहुत कुछ चुरा लिया। CloudSEK डेटा से पता चलता है कि 2,100 से अधिक संगठन उजागर हो सकते हैं।"
original_url: "https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html"
source: "The Hacker News"
severity: "High"
target: "PyPI पर LiteLLM उपयोगकर्ता"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

PyPI पर दो दुर्भावनापूर्ण LiteLLM पैकेजों ने क्लाउड कुंजियाँ, SSH कुंजियाँ और बहुत कुछ चुरा लिया। CloudSEK डेटा से पता चलता है कि 2,100 से अधिक संगठन उजागर हो सकते हैं।

{{< cyber-report severity="High" source="The Hacker News" target="PyPI पर LiteLLM उपयोगकर्ता" >}}

मार्च में PyPI पर दो दुर्भावनापूर्ण LiteLLM रिलीज़ प्रकाशित की गईं और लगभग 40 मिनट तक उपलब्ध रहीं। इन पैकेजों में क्रेडेंशियल-चोरी करने वाला कोड था जो क्लाउड एक्सेस कुंजियों, SSH निजी कुंजियों, Kubernetes टोकन और डेटाबेस पासवर्ड सहित कई प्रकार के रहस्यों को इकट्ठा करने के लिए डिज़ाइन किया गया था, जो उन्हें स्थापित करने वाले किसी भी सिस्टम से प्राप्त होते थे।

{{< ad-banner >}}

खतरे की खुफिया फर्म CloudSEK ने हमलावरों द्वारा कैप्चर की गई लगभग 434,000 फाइलों से निर्मित एक डेटासेट प्राप्त किया। इस डेटासेट के विश्लेषण से पता चलता है कि यह जोखिम 2,100 से अधिक संगठनों को प्रभावित कर सकता है, जो समझौते के संभावित पैमाने को उजागर करता है।

यह घटना पहले के Trivy हैक से जुड़ी है, जो एक समन्वित आपूर्ति श्रृंखला हमले का संकेत देती है। जिन संगठनों ने प्रभावित अवधि के दौरान PyPI से LiteLLM स्थापित किया है, उन्हें तुरंत सभी उजागर क्रेडेंशियल्स को घुमाना चाहिए और अनधिकृत पहुंच के संकेतों की जांच करनी चाहिए।

{{< netrunner-insight >}}

यह घटना सॉफ्टवेयर आपूर्ति श्रृंखला सतर्कता की महत्वपूर्ण आवश्यकता को रेखांकित करती है। SOC विश्लेषकों को दुर्भावनापूर्ण LiteLLM संस्करणों के किसी भी इंस्टॉलेशन की निगरानी करनी चाहिए और किसी भी संभावित रूप से उजागर रहस्यों के लिए क्रेडेंशियल रोटेशन को प्राथमिकता देनी चाहिए। DevSecOps टीमों को सख्त पैकेज अखंडता जांच लागू करनी चाहिए और ऐसे जोखिमों को कम करने के लिए हैश के साथ निजी मिरर या लॉक फाइलों का उपयोग करने पर विचार करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html)**
