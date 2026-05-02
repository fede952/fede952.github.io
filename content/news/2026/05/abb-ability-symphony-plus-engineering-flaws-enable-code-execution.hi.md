---
title: "ABB Ability Symphony Plus Engineering में खामियां कोड निष्पादन को सक्षम बनाती हैं"
date: "2026-05-02T08:20:38Z"
original_date: "2026-04-30T12:00:00"
lang: "hi"
translationKey: "abb-ability-symphony-plus-engineering-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA ने ABB Ability Symphony Plus Engineering में पुराने PostgreSQL के कारण कमजोरियों की चेतावनी दी है, जो प्रभावित सिस्टम पर मनमाना कोड निष्पादन की अनुमति देती हैं।"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06"
source: "CISA"
severity: "High"
target: "ABB Ability Symphony Plus Engineering"
cve: "CVE-2023-5869"
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA ने ABB Ability Symphony Plus Engineering में पुराने PostgreSQL के कारण कमजोरियों की चेतावनी दी है, जो प्रभावित सिस्टम पर मनमाना कोड निष्पादन की अनुमति देती हैं।

{{< cyber-report severity="High" source="CISA" target="ABB Ability Symphony Plus Engineering" cve="CVE-2023-5869" cvss="8.8" >}}

CISA ने एक सलाह (ICSA-26-120-06) जारी की है जिसमें ABB Ability Symphony Plus Engineering में कई कमजोरियों का विवरण दिया गया है, जो PostgreSQL संस्करण 13.11 और उससे पहले के उपयोग से उत्पन्न होती हैं। इन खामियों में इंटीजर ओवरफ्लो, SQL इंजेक्शन, TOCTOU रेस कंडीशन और प्रिविलेज ड्रॉपिंग त्रुटियां शामिल हैं, जो एक प्रमाणित हमलावर को सिस्टम पर मनमाना कोड निष्पादित करने की अनुमति दे सकती हैं।

{{< ad-banner >}}

प्रभावित संस्करण Ability Symphony Plus 2.2 से 2.4 SP2 RU1 तक फैले हुए हैं। ये कमजोरियां विशेष रूप से चिंताजनक हैं क्योंकि उत्पाद दुनिया भर में रासायनिक, महत्वपूर्ण विनिर्माण, ऊर्जा, और जल एवं अपशिष्ट जल जैसे महत्वपूर्ण बुनियादी ढांचा क्षेत्रों में तैनात है।

सबसे उल्लेखनीय कमजोरी, CVE-2023-5869, का CVSS स्कोर 8.8 है और इसमें एक इंटीजर ओवरफ्लो शामिल है जो एक प्रमाणित PostgreSQL उपयोगकर्ता द्वारा तैयार किए गए डेटा से ट्रिगर किया जा सकता है। सफल शोषण से पूर्ण सिस्टम समझौता हो सकता है, जो तत्काल पैचिंग की आवश्यकता पर बल देता है।

{{< netrunner-insight >}}

यह सलाह OT वातावरण में पुरानी निर्भरताओं के जोखिम को रेखांकित करती है। SOC विश्लेषकों को ABB Symphony Plus इंस्टेंस के लिए एसेट डिस्कवरी को प्राथमिकता देनी चाहिए और सुनिश्चित करना चाहिए कि PostgreSQL को 13.11 से ऊपर अपडेट किया गया है। DevSecOps टीमों को औद्योगिक नियंत्रण प्रणालियों के लिए CI/CD पाइपलाइनों में डिपेंडेंसी स्कैनिंग को एकीकृत करना चाहिए ताकि ऐसी विरासत कमजोरियों को जल्दी पकड़ा जा सके।

{{< /netrunner-insight >}}

---

**[पूरा लेख CISA पर पढ़ें ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06)**
