---
title: "CISA ने Siemens RUGGEDCOM APE1808 में PAN-OS के माध्यम से क्रिटिकल बफर ओवरफ्लो की चेतावनी दी"
date: "2026-05-20T10:21:56Z"
original_date: "2026-05-19T12:00:00"
lang: "hi"
translationKey: "cisa-warns-of-critical-buffer-overflow-in-siemens-ruggedcom-ape1808-via-pan-os"
author: "NewsBot (Validated by Federico Sella)"
description: "Palo Alto Networks PAN-OS Captive Portal में एक बफर ओवरफ्लो Siemens RUGGEDCOM APE1808 उपकरणों को प्रभावित करता है। CVE-2026-0300 बिना प्रमाणीकरण के रूट विशेषाधिकारों के साथ दूरस्थ कोड निष्पादन की अनुमति देता है।"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02"
source: "CISA"
severity: "Critical"
target: "Siemens RUGGEDCOM APE1808 उपकरण"
cve: "CVE-2026-0300"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Palo Alto Networks PAN-OS Captive Portal में एक बफर ओवरफ्लो Siemens RUGGEDCOM APE1808 उपकरणों को प्रभावित करता है। CVE-2026-0300 बिना प्रमाणीकरण के रूट विशेषाधिकारों के साथ दूरस्थ कोड निष्पादन की अनुमति देता है।

{{< cyber-report severity="Critical" source="CISA" target="Siemens RUGGEDCOM APE1808 उपकरण" cve="CVE-2026-0300" cvss="10.0" >}}

CISA ने एक सलाह (ICSA-26-139-02) प्रकाशित की है जिसमें Palo Alto Networks PAN-OS सॉफ्टवेयर की User-ID Authentication Portal (Captive Portal) सेवा में एक क्रिटिकल बफर ओवरफ्लो भेद्यता का विवरण दिया गया है। यह दोष, जिसे CVE-2026-0300 के रूप में ट्रैक किया गया है और CVSS स्कोर 10.0 है, एक अप्रमाणित हमलावर को PA-Series और VM-Series फायरवॉल पर विशेष रूप से तैयार पैकेट भेजकर रूट विशेषाधिकारों के साथ मनमाना कोड निष्पादित करने की अनुमति देता है।

{{< ad-banner >}}

यह भेद्यता सभी संस्करणों पर चलने वाले Siemens RUGGEDCOM APE1808 उपकरणों को प्रभावित करती है। Siemens फिक्स संस्करण तैयार कर रहा है और Palo Alto Networks के अपस्ट्रीम सुरक्षा नोटिस में दिए गए वर्कअराउंड को लागू करने की सिफारिश करता है। जब तक पैच उपलब्ध नहीं हो जाते, संगठनों को Captive Portal सेवा को अक्षम कर देना चाहिए यदि इसकी आवश्यकता नहीं है और प्रभावित उपकरणों तक नेटवर्क पहुंच को प्रतिबंधित करना चाहिए।

क्रिटिकल CVSS स्कोर और पूर्ण सिस्टम समझौता की संभावना को देखते हुए, तत्काल कार्रवाई आवश्यक है। यह सलाह क्रिटिकल मैन्युफैक्चरिंग सेक्टर को लक्षित करती है, जिसमें दुनिया भर में तैनात उपकरण शामिल हैं। ऑपरेटरों को शमन उपायों को लागू करने और शोषण के किसी भी संकेत के लिए निगरानी करने को प्राथमिकता देनी चाहिए।

{{< netrunner-insight >}}

यह आपूर्ति श्रृंखला जोखिम का एक उत्कृष्ट उदाहरण है: एक तृतीय-पक्ष घटक (PAN-OS) एक औद्योगिक उत्पाद में एक क्रिटिकल दोष पेश करता है। SOC विश्लेषकों को तुरंत Captive Portal पोर्ट पर असामान्य ट्रैफ़िक की खोज करनी चाहिए और सुनिश्चित करना चाहिए कि सेगमेंटेशन एक्सपोजर को सीमित करता है। DevSecOps टीमों को RUGGEDCOM APE1808 के सभी इंस्टेंस की सूची बनानी चाहिए और बिना देरी के अपस्ट्रीम Palo Alto Networks शमन उपायों को लागू करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख CISA पर पढ़ें ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02)**
