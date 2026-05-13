---
title: "Subnet Solutions PowerSYSTEM Center में खामियां सूचना लीक और CRLF इंजेक्शन को सक्षम बनाती हैं"
date: "2026-05-13T09:40:06Z"
original_date: "2026-05-12T12:00:00"
lang: "hi"
translationKey: "subnet-solutions-powersystem-center-flaws-enable-info-leak-crlf-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA ने Subnet Solutions PowerSYSTEM Center में कई कमजोरियों के बारे में चेतावनी दी है, जिसमें सूचना प्रकटीकरण और CRLF इंजेक्शन शामिल हैं, जो 2020 से 2026 तक के संस्करणों को प्रभावित करती हैं।"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02"
source: "CISA"
severity: "High"
target: "Subnet Solutions PowerSYSTEM Center"
cve: "CVE-2026-35504"
cvss: 8.2
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA ने Subnet Solutions PowerSYSTEM Center में कई कमजोरियों के बारे में चेतावनी दी है, जिसमें सूचना प्रकटीकरण और CRLF इंजेक्शन शामिल हैं, जो 2020 से 2026 तक के संस्करणों को प्रभावित करती हैं।

{{< cyber-report severity="High" source="CISA" target="Subnet Solutions PowerSYSTEM Center" cve="CVE-2026-35504" cvss="8.2" >}}

CISA ने एक सलाह (ICSA-26-132-02) जारी की है जिसमें Subnet Solutions PowerSYSTEM Center में कई कमजोरियों का विवरण दिया गया है, जो महत्वपूर्ण विनिर्माण और ऊर्जा क्षेत्रों में उपयोग किया जाने वाला एक प्लेटफॉर्म है। इन खामियों में गलत प्राधिकरण (CVE-2026-26289) शामिल है जो सीमित अनुमतियों वाले प्रमाणित उपयोगकर्ताओं को डिवाइस खातों को निर्यात करने और संवेदनशील जानकारी को उजागर करने की अनुमति देता है जो सामान्यतः प्रशासकों तक सीमित होती है। इसके अतिरिक्त, CRLF इंजेक्शन कमजोरियां (CVE-2026-35504, CVE-2026-33570, CVE-2026-35555) हमलावरों को दुर्भावनापूर्ण हेडर या प्रतिक्रियाएं इंजेक्ट करने में सक्षम बना सकती हैं।

{{< ad-banner >}}

प्रभावित संस्करण PowerSYSTEM Center 2020 (5.8.x से 5.28.x), 2024 (6.0.x से 6.1.x), और 2026 (7.0.x) तक फैले हुए हैं। कमजोरियों का CVSS v3 बेस स्कोर 8.2 है, जो उच्च गंभीरता को दर्शाता है। सफल शोषण से सूचना प्रकटीकरण और संभावित सत्र हेरफेर या HTTP प्रतिक्रिया विभाजन हो सकता है।

दुनिया भर में महत्वपूर्ण बुनियादी ढांचे में उत्पाद की तैनाती को देखते हुए, संगठनों को पैचिंग को प्राथमिकता देनी चाहिए। Subnet Solutions ने संभवतः अपडेट जारी किए हैं; प्रशासकों को सलाह दी जाती है कि वे विक्रेता की सुरक्षा सलाहकार से परामर्श करें और नवीनतम पैच लागू करें। तब तक, PowerSYSTEM Center तक नेटवर्क पहुंच को प्रतिबंधित करें और असामान्य गतिविधि की निगरानी करें।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, असामान्य डिवाइस खाता निर्यात के लिए प्रमाणीकरण लॉग की निगरानी करें—यह CVE-2026-26289 शोषण का एक स्पष्ट संकेत है। DevSecOps टीमों को तुरंत PowerSYSTEM Center संस्करणों की सूची बनानी चाहिए और पैच लागू करने चाहिए, क्योंकि CRLF इंजेक्शन वेक्टर (CVE-2026-35504 et al.) को अन्य हमलों के साथ जोड़कर सत्र अखंडता से समझौता किया जा सकता है। CVSS 8.2 स्कोर और महत्वपूर्ण क्षेत्र के जोखिम को देखते हुए इसे उच्च-प्राथमिकता वाले सुधार के रूप में मानें।

{{< /netrunner-insight >}}

---

**[पूरा लेख CISA पर पढ़ें ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02)**
