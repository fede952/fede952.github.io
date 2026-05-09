---
title: "नया PamDOORa Linux बैकडोर PAM के माध्यम से SSH क्रेडेंशियल चुराता है"
date: "2026-05-09T08:29:08Z"
original_date: "2026-05-08T08:41:00"
lang: "hi"
translationKey: "new-pamdoora-linux-backdoor-steals-ssh-credentials-via-pam"
author: "NewsBot (Validated by Federico Sella)"
description: "PamDOORa नामक एक नया Linux बैकडोर, जो एक रूसी साइबर अपराध फोरम पर $1,600 में बेचा जा रहा है, एक मैजिक पासवर्ड और TCP पोर्ट संयोजन के साथ स्थायी SSH पहुंच प्रदान करने के लिए PAM मॉड्यूल का उपयोग करता है।"
original_url: "https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html"
source: "The Hacker News"
severity: "High"
target: "Linux SSH सर्वर"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

PamDOORa नामक एक नया Linux बैकडोर, जो एक रूसी साइबर अपराध फोरम पर $1,600 में बेचा जा रहा है, एक मैजिक पासवर्ड और TCP पोर्ट संयोजन के साथ स्थायी SSH पहुंच प्रदान करने के लिए PAM मॉड्यूल का उपयोग करता है।

{{< cyber-report severity="High" source="The Hacker News" target="Linux SSH सर्वर" >}}

साइबर सुरक्षा शोधकर्ताओं ने PamDOORa नामक एक नया Linux बैकडोर खोजा है, जिसे 'darkworm' नामक एक खतरे वाले अभिनेता द्वारा Rehub रूसी साइबर अपराध फोरम पर $1,600 में विज्ञापित किया गया है। यह बैकडोर एक प्लगेबल ऑथेंटिकेशन मॉड्यूल (PAM) आधारित पोस्ट-एक्सप्लॉइटेशन टूलकिट के रूप में डिज़ाइन किया गया है, जो एक मैजिक पासवर्ड और एक विशिष्ट TCP पोर्ट के संयोजन के माध्यम से स्थायी SSH पहुंच सक्षम करता है।

{{< ad-banner >}}

PamDOORa दुर्भावनापूर्ण PAM मॉड्यूल के माध्यम से SSH प्रमाणीकरण को इंटरसेप्ट करके काम करता है, जिससे हमलावर सामान्य क्रेडेंशियल को बायपास करके अनधिकृत पहुंच प्राप्त कर सकते हैं। PAM मॉड्यूल का उपयोग बैकडोर को गुप्त बनाता है, क्योंकि यह Linux सिस्टम के मानक प्रमाणीकरण प्रवाह में एकीकृत हो जाता है।

साइबर अपराध फोरम पर ऐसे उपकरणों की बिक्री परिष्कृत हमले उपकरणों के बढ़ते कमोडिटीकरण को उजागर करती है। संगठनों को असामान्य SSH प्रमाणीकरण पैटर्न की निगरानी करने और PAM कॉन्फ़िगरेशन की नियमित रूप से ऑडिट सुनिश्चित करने की सलाह दी जाती है।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, PamDOORa का पता लगाने के लिए गैर-मानक पोर्ट पर अप्रत्याशित SSH कनेक्शन की निगरानी और PAM मॉड्यूल परिवर्तनों के साथ सहसंबंध की आवश्यकता होती है। DevSecOps टीमों को सख्त PAM कॉन्फ़िगरेशन प्रबंधन लागू करना चाहिए और /etc/pam.d/ और संबंधित लाइब्रेरी के लिए फ़ाइल अखंडता निगरानी पर विचार करना चाहिए। यह बैकडोर PAM को एक महत्वपूर्ण सुरक्षा सीमा के रूप में मानने के महत्व को रेखांकित करता है।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html)**
