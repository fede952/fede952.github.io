---
title: "CISA ने Rockwell RSLinx Classic में DoS की ओर ले जाने वाली खामी के बारे में चेतावनी दी"
date: "2026-06-17T11:42:55Z"
original_date: "2026-06-16T12:00:00"
lang: "hi"
translationKey: "cisa-warns-of-rockwell-rslinx-classic-flaw-leading-to-dos"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA सलाहकार CVE-2020-13573 को उजागर करता है, जो Rockwell Automation RSLinx Classic ≤4.50.00 में एक स्टैक-आधारित बफर ओवरफ्लो है, जिससे सेवा से इनकार और दूरस्थ कोड निष्पादन का जोखिम होता है।"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02"
source: "CISA"
severity: "High"
target: "Rockwell Automation RSLinx Classic"
cve: "CVE-2020-13573"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA सलाहकार CVE-2020-13573 को उजागर करता है, जो Rockwell Automation RSLinx Classic ≤4.50.00 में एक स्टैक-आधारित बफर ओवरफ्लो है, जिससे सेवा से इनकार और दूरस्थ कोड निष्पादन का जोखिम होता है।

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation RSLinx Classic" cve="CVE-2020-13573" cvss="7.5" >}}

CISA ने Rockwell Automation RSLinx Classic, एक व्यापक रूप से उपयोग किए जाने वाले औद्योगिक संचार सॉफ्टवेयर में एक कमजोरी के संबंध में एक सलाह (ICSA-26-167-02) जारी की है। CVE-2020-13573 के रूप में पहचानी गई यह खामी एक स्टैक-आधारित बफर ओवरफ्लो है जिसका दूरस्थ रूप से शोषण करके मनमाना कोड निष्पादित किया जा सकता है या सेवा से इनकार किया जा सकता है, जिससे एप्लिकेशन अनुत्तरदायी हो जाता है और स्वचालित रूप से पुनर्प्राप्त नहीं हो पाता।

{{< ad-banner >}}

प्रभावित संस्करणों में RSLinx Classic संस्करण 4.50.00 तक शामिल हैं। इस कमजोरी का CVSS v3 स्कोर 7.5 है, जो उच्च गंभीरता को दर्शाता है। Rockwell Automation संस्करण 4.60.00 या बाद में अपग्रेड करने, या तत्काल अपग्रेड करने में असमर्थ ग्राहकों के लिए पैच BF31213 लागू करने की अनुशंसा करता है। सलाह में अंतर्निहित कमजोरी के रूप में CWE-125 (आउट-ऑफ-बाउंड्स रीड) का भी उल्लेख किया गया है।

शामिल महत्वपूर्ण बुनियादी ढांचा क्षेत्रों—क्रिटिकल मैन्युफैक्चरिंग, ऊर्जा, खाद्य और कृषि, और जल और अपशिष्ट जल—और उत्पाद के वैश्विक परिनियोजन को देखते हुए, समय पर पैचिंग आवश्यक है। संगठनों को इस अद्यतन को प्राथमिकता देनी चाहिए ताकि शोषण के जोखिम को कम किया जा सके, विशेष रूप से उन वातावरणों में जहां RSLinx Classic अविश्वसनीय नेटवर्क के संपर्क में है।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, RSLinx Classic प्रक्रियाओं में असामान्य क्रैश या अनुत्तरदायीता की निगरानी करें, क्योंकि ये शोषण प्रयासों का संकेत हो सकते हैं। DevSecOps टीमों को तुरंत संस्करण 4.60.00 में अपग्रेड करने या पैच BF31213 लागू करने की योजना बनानी चाहिए, और सुनिश्चित करना चाहिए कि RSLinx इंस्टेंस इंटरनेट से सीधे सुलभ न हों। CVSS स्कोर और दूरस्थ कोड निष्पादन की संभावना को देखते हुए, इसे उच्च-प्राथमिकता वाली सुधारात्मक वस्तु मानें।

{{< /netrunner-insight >}}

---

**[पूरा लेख CISA पर पढ़ें ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02)**
