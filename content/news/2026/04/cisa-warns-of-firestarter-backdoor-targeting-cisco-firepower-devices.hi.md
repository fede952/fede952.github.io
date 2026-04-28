---
title: "CISA ने Cisco Firepower उपकरणों को लक्षित करने वाले FIRESTARTER बैकडोर के बारे में चेतावनी दी"
date: "2026-04-23T12:00:00"
lang: "hi"
translationKey: "cisa-warns-of-firestarter-backdoor-targeting-cisco-firepower-devices"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA और NCSC ने Cisco ASA/FTD उपकरणों पर स्थिरता के लिए FIRESTARTER बैकडोर का उपयोग करने वाले APT अभिनेताओं के बारे में सतर्क किया। तत्काल प्रतिक्रिया कार्रवाइयों की रूपरेखा दी गई।"
original_url: "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"
source: "CISA"
severity: "High"
target: "Cisco Firepower और Secure Firewall उपकरण"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA और NCSC ने Cisco ASA/FTD उपकरणों पर स्थिरता के लिए FIRESTARTER बैकडोर का उपयोग करने वाले APT अभिनेताओं के बारे में सतर्क किया। तत्काल प्रतिक्रिया कार्रवाइयों की रूपरेखा दी गई।

{{< cyber-report severity="High" source="CISA" target="Cisco Firepower और Secure Firewall उपकरण" >}}

CISA और UK NCSC ने FIRESTARTER बैकडोर पर एक मैलवेयर विश्लेषण रिपोर्ट जारी की है, जिसका उपयोग उन्नत सतत खतरे (APT) अभिनेताओं द्वारा ASA या FTD सॉफ़्टवेयर चलाने वाले सार्वजनिक रूप से सुलभ Cisco Firepower और Secure Firewall उपकरणों पर स्थिरता बनाए रखने के लिए किया जा रहा है। विश्लेषण एक फोरेंसिक जांच से प्राप्त नमूने पर आधारित है, और CISA ने ASA सॉफ़्टवेयर वाले Cisco Firepower उपकरणों पर सफल वास्तविक दुनिया के इम्प्लांट की पुष्टि की है।

{{< ad-banner >}}

यह रिलीज़ CISA के आपातकालीन निर्देश 25-03 के अनुरूप है, जिसमें अमेरिकी FCEB एजेंसियों से कोर डंप एकत्र करने और CISA के Malware Next Generation प्लेटफ़ॉर्म पर सबमिट करने तथा 24/7 संचालन केंद्र के माध्यम से तुरंत सबमिशन की रिपोर्ट करने का आग्रह किया गया है। संगठनों को सलाह दी जाती है कि जब तक CISA अगले कदम नहीं बताता, तब तक कोई अतिरिक्त कार्रवाई न करें।

जबकि मैलवेयर Cisco Firepower और Secure Firewall दोनों उपकरणों के लिए प्रासंगिक है, CISA ने केवल ASA चलाने वाले Firepower उपकरणों पर सफल इम्प्लांट देखे हैं। रिपोर्ट सतर्कता और समझौता संकेतकों के लिए सक्रिय खोज की आवश्यकता पर जोर देती है।

{{< netrunner-insight >}}

SOC विश्लेषकों को Cisco ASA/FTD उपकरणों से कोर डंप एकत्र करने और उन्हें विश्लेषण के लिए CISA को सबमिट करने को प्राथमिकता देनी चाहिए। DevSecOps टीमों को यह सुनिश्चित करना चाहिए कि Cisco उपकरणों को सर्वोत्तम प्रथाओं के अनुसार पैच और कॉन्फ़िगर किया गया है, और असामान्य स्थिरता तंत्रों की निगरानी करें। यह बैकडोर APT-स्तरीय खतरों के विरुद्ध नेटवर्क एज उपकरणों को सुरक्षित करने की महत्वपूर्णता को उजागर करता है।

{{< /netrunner-insight >}}

---

**[पूरा लेख CISA पर पढ़ें ›](https://www.cisa.gov/news-events/analysis-reports/ar26-113a)**
