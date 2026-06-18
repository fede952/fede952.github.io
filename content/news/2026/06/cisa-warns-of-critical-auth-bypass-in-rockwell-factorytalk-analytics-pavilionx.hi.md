---
title: "CISA ने Rockwell FactoryTalk Analytics PavilionX में क्रिटिकल ऑथ बाइपास की चेतावनी दी"
date: "2026-06-18T11:06:01Z"
original_date: "2026-06-16T12:00:00"
lang: "hi"
translationKey: "cisa-warns-of-critical-auth-bypass-in-rockwell-factorytalk-analytics-pavilionx"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA ने CVE-2025-14272 के बारे में चेतावनी दी है जो Rockwell Automation FactoryTalk Analytics PavilionX <7.01 को प्रभावित करता है, जो महत्वपूर्ण विनिर्माण वातावरण में अनधिकृत विशेषाधिकार संचालन की अनुमति देता है।"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01"
source: "CISA"
severity: "High"
target: "Rockwell FactoryTalk Analytics PavilionX"
cve: "CVE-2025-14272"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA ने CVE-2025-14272 के बारे में चेतावनी दी है जो Rockwell Automation FactoryTalk Analytics PavilionX <7.01 को प्रभावित करता है, जो महत्वपूर्ण विनिर्माण वातावरण में अनधिकृत विशेषाधिकार संचालन की अनुमति देता है।

{{< cyber-report severity="High" source="CISA" target="Rockwell FactoryTalk Analytics PavilionX" cve="CVE-2025-14272" >}}

CISA ने Rockwell Automation FactoryTalk Analytics PavilionX में एक अनुपस्थित प्राधिकरण भेद्यता के संबंध में एक सलाह (ICSA-26-167-01) प्रकाशित की है। CVE-2025-14272 के रूप में ट्रैक की गई यह खामी संस्करण 7.01 से पहले के संस्करणों को प्रभावित करती है और एक अनधिकृत हमलावर को उपयोगकर्ता और भूमिका प्रबंधन जैसे विशेषाधिकार संचालन करने की अनुमति देती है।

{{< ad-banner >}}

यह भेद्यता API एंडपॉइंट में अनुचित प्राधिकरण प्रवर्तन से उत्पन्न होती है। सफल शोषण से प्रभावित सिस्टम पर पूर्ण प्रशासनिक नियंत्रण हो सकता है। Rockwell Automation ने इस मुद्दे को ठीक करने के लिए संस्करण 7.01 जारी किया है, और उपयोगकर्ताओं को तुरंत अपग्रेड करने का आग्रह किया गया है।

दुनिया भर में महत्वपूर्ण विनिर्माण क्षेत्रों में इस उत्पाद की तैनाती को देखते हुए, परिचालन व्यवधान या डेटा समझौता का जोखिम महत्वपूर्ण है। संगठनों को पैचिंग को प्राथमिकता देनी चाहिए और संभावित शोषण को कम करने के लिए पहुंच नियंत्रण की समीक्षा करनी चाहिए।

{{< netrunner-insight >}}

यह एक क्लासिक प्राधिकरण बाइपास है जिसे उच्च-प्राथमिकता वाले पैच के रूप में माना जाना चाहिए। SOC विश्लेषकों को PavilionX वातावरण में असामान्य API कॉल या विशेषाधिकार वृद्धि की निगरानी करनी चाहिए। DevSecOps टीमों को यह सुनिश्चित करना चाहिए कि संस्करण 7.01 तैनात किया गया है और नेटवर्क विभाजन इन एंडपॉइंट के जोखिम को सीमित करता है।

{{< /netrunner-insight >}}

---

**[पूरा लेख CISA पर पढ़ें ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01)**
