---
title: "अकीरा रैंसमवेयर सहयोगी सेफ मोड के माध्यम से EDR को बायपास करता है, डेटा एक्सफिल्ट्रेट करता है"
date: "2026-08-16T07:35:41Z"
original_date: "2026-08-13T20:47:02"
lang: "hi"
translationKey: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
slug: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
author: "NewsBot (Validated by Federico Sella)"
description: "अकीरा रैंसमवेयर सहयोगी ने नेटवर्किंग के साथ सेफ मोड में बूट करके EDR को अक्षम कर दिया, डेटा चुराया लेकिन एन्क्रिप्ट करने में विफल रहा। बचाव के तरीके जानें।"
original_url: "https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/"
source: "BleepingComputer"
severity: "High"
target: "एंडपॉइंट डिटेक्शन एंड रिस्पांस (EDR) समाधान"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

अकीरा रैंसमवेयर सहयोगी ने नेटवर्किंग के साथ सेफ मोड में बूट करके EDR को अक्षम कर दिया, डेटा चुराया लेकिन एन्क्रिप्ट करने में विफल रहा। बचाव के तरीके जानें।

{{< cyber-report severity="High" source="BleepingComputer" target="एंडपॉइंट डिटेक्शन एंड रिस्पांस (EDR) समाधान" >}}

अकीरा रैंसमवेयर सहयोगी को समझौता किए गए सिस्टम पर मशीन को नेटवर्किंग के साथ सेफ मोड में पुनः आरंभ करके एंडपॉइंट डिटेक्शन एंड रिस्पांस (EDR) समाधानों को अक्षम करते हुए देखा गया है। यह तकनीक हमलावर को EDR निगरानी के बिना काम करने की अनुमति देती है, क्योंकि कई सुरक्षा उपकरण सेफ मोड में लोड नहीं होते हैं।

{{< ad-banner >}}

सहयोगी ने पीड़ित के नेटवर्क से संवेदनशील डेटा सफलतापूर्वक एक्सफिल्ट्रेट किया, लेकिन हमले का एन्क्रिप्शन चरण विफल रहा। यह बताता है कि जबकि EDR बायपास प्रभावी था, अन्य सुरक्षा नियंत्रण या परिचालन संबंधी मुद्दों ने अंतिम रैंसमवेयर पेलोड को ठीक से निष्पादित होने से रोक दिया।

यह घटना बूट कॉन्फ़िगरेशन को सख्त करने और अप्रत्याशित सिस्टम पुनः आरंभ की निगरानी करने के महत्व को उजागर करती है, विशेष रूप से सेफ मोड में। संगठनों को यह भी सुनिश्चित करना चाहिए कि EDR समाधानों में टैम्पर प्रोटेक्शन सक्षम हो और सेफ मोड बूट प्रतिबंधित या निगरानी में हो।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, यह एक अनुस्मारक है कि EDR बायपास सेफ मोड में रिबूट जितना सरल हो सकता है। असामान्य शटडाउन/रीस्टार्ट इवेंट की निगरानी करें और BIOS/UEFI पासवर्ड या समूह नीति के माध्यम से सेफ मोड बूट को अक्षम करने पर विचार करें। DevSecOps को यह सुनिश्चित करना चाहिए कि EDR एजेंट सेफ मोड में शुरू करने के लिए कॉन्फ़िगर किए गए हैं और इस सामान्य चोरी तकनीक को रोकने के लिए टैम्पर प्रोटेक्शन लागू किया गया है।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/)**
