---
title: "ABB IEC 61850 स्टैक में खामी औद्योगिक नियंत्रण प्रणालियों पर DoS हमले को सक्षम बनाती है"
date: "2026-05-01T09:03:14Z"
original_date: "2026-04-30T12:00:00"
lang: "hi"
translationKey: "abb-iec-61850-stack-flaw-enables-dos-on-industrial-control-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA ने ABB के IEC 61850 MMS कार्यान्वयन में एक निजी तौर पर रिपोर्ट की गई कमजोरी के बारे में चेतावनी दी है, जो System 800xA और Symphony Plus उत्पादों को प्रभावित करती है, जिससे उपकरण दोष और सेवा-अस्वीकार हो सकता है।"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01"
source: "CISA"
severity: "High"
target: "ABB System 800xA, Symphony Plus IEC 61850"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA ने ABB के IEC 61850 MMS कार्यान्वयन में एक निजी तौर पर रिपोर्ट की गई कमजोरी के बारे में चेतावनी दी है, जो System 800xA और Symphony Plus उत्पादों को प्रभावित करती है, जिससे उपकरण दोष और सेवा-अस्वीकार हो सकता है।

{{< cyber-report severity="High" source="CISA" target="ABB System 800xA, Symphony Plus IEC 61850" >}}

CISA ने MMS क्लाइंट अनुप्रयोगों के लिए IEC 61850 संचार स्टैक के ABB कार्यान्वयन में एक कमजोरी के संबंध में एक सलाह (ICSA-26-120-01) जारी की है। यह खामी System 800xA और Symphony Plus लाइनों के कई उत्पादों को प्रभावित करती है, जिनमें AC800M CI868, Symphony Plus SD Series CI850, PM 877, और S+ Operations शामिल हैं। शोषण के लिए साइट के IEC 61850 नेटवर्क तक पूर्व पहुंच की आवश्यकता होती है।

{{< ad-banner >}}

सफल शोषण PM 877, CI850, और CI868 मॉड्यूल पर उपकरण दोष का कारण बनता है, जिससे मैन्युअल पुनरारंभ की आवश्यकता होती है। S+ Operations नोड्स के लिए, हमला IEC 61850 संचार ड्राइवर को क्रैश कर देता है, जिससे बार-बार होने पर सेवा-अस्वीकार की स्थिति उत्पन्न होती है। हालांकि, समग्र नोड उपलब्धता और कार्यक्षमता अप्रभावित रहती है, और GOOSE प्रोटोकॉल संचार प्रभावित नहीं होता है। System 800xA IEC61850 Connect भी कमजोर नहीं है।

प्रभावित फर्मवेयर संस्करण कई शाखाओं में फैले हुए हैं, जिनमें S+ Operations 6.2.0006.0 तक और विभिन्न PM 877 रिलीज़ शामिल हैं। सलाह में कोई CVE पहचानकर्ता या CVSS स्कोर प्रदान नहीं किया गया था। इन उत्पादों का उपयोग करने वाले संगठनों को सलाह की समीक्षा करनी चाहिए और IEC 61850 नेटवर्क के जोखिम को सीमित करने के लिए नेटवर्क विभाजन और पहुंच नियंत्रण जैसे उपायों को लागू करना चाहिए।

{{< netrunner-insight >}}

यह कमजोरी OT वातावरण में नेटवर्क विभाजन के महत्व को रेखांकित करती है। चूंकि शोषण के लिए IEC 61850 नेटवर्क तक पहुंच की आवश्यकता होती है, इसलिए उस नेटवर्क को कॉर्पोरेट IT और इंटरनेट से अलग करना महत्वपूर्ण है। SOC विश्लेषकों को असामान्य IEC 61850 ट्रैफ़िक की निगरानी करनी चाहिए, जबकि DevSecOps इंजीनियरों को पैचिंग को प्राथमिकता देनी चाहिए और MMS प्रोटोकॉल विसंगतियों के लिए घुसपैठ का पता लगाने पर विचार करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख CISA पर पढ़ें ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01)**
