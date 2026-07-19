---
title: "7-Zip 26.02 ने दुर्भावनापूर्ण आर्काइव में RCE दोष को ठीक किया"
date: "2026-07-19T09:02:18Z"
original_date: "2026-07-18T19:32:02"
lang: "hi"
translationKey: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
slug: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
author: "NewsBot (Validated by Federico Sella)"
description: "7-Zip ने संस्करण 26.02 जारी किया है ताकि एक रिमोट कोड निष्पादन भेद्यता को ठीक किया जा सके जो विशेष रूप से तैयार किए गए संपीड़ित फ़ाइलों को खोलने पर ट्रिगर हो सकती है। तुरंत अपडेट करें।"
original_url: "https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/"
source: "BleepingComputer"
severity: "High"
target: "7-Zip उपयोगकर्ता"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

7-Zip ने संस्करण 26.02 जारी किया है ताकि एक रिमोट कोड निष्पादन भेद्यता को ठीक किया जा सके जो विशेष रूप से तैयार किए गए संपीड़ित फ़ाइलों को खोलने पर ट्रिगर हो सकती है। तुरंत अपडेट करें।

{{< cyber-report severity="High" source="BleepingComputer" target="7-Zip उपयोगकर्ता" >}}

7-Zip संस्करण 26.02 को एक रिमोट कोड निष्पादन (RCE) भेद्यता को संबोधित करने के लिए जारी किया गया है जो हमलावरों को पीड़ित के सिस्टम पर मनमाना कोड निष्पादित करने की अनुमति दे सकती है। यह दोष उपयोगकर्ताओं को विशेष रूप से तैयार संपीड़ित फ़ाइलों, जैसे दुर्भावनापूर्ण पेलोड वाले आर्काइव, खोलने के लिए राजी करके शोषणीय है।

{{< ad-banner >}}

यह भेद्यता लोकप्रिय फ़ाइल आर्काइवर के सभी पिछले संस्करणों को प्रभावित करती है। हालांकि घोषणा में कोई CVE पहचानकर्ता का खुलासा नहीं किया गया है, लेकिन पूर्ण सिस्टम समझौता की संभावना के कारण गंभीरता को उच्च माना जाता है। उपयोगकर्ताओं को दृढ़ता से सलाह दी जाती है कि वे तुरंत नवीनतम संस्करण में अपडेट करें।

एंटरप्राइज़ और उपभोक्ता दोनों वातावरणों में 7-Zip के व्यापक उपयोग को देखते हुए, यह पैच हमले की सतह को कम करने के लिए महत्वपूर्ण है। संगठनों को स्वचालित अपडेट तंत्र या मैन्युअल स्थापना के माध्यम से तैनाती को प्राथमिकता देनी चाहिए।

{{< netrunner-insight >}}

SOC विश्लेषकों को असामान्य आर्काइव फ़ाइल गतिविधि की निगरानी करनी चाहिए और सुनिश्चित करना चाहिए कि सभी एंडपॉइंट पर 7-Zip अपडेट किया गया है। DevSecOps टीमों को इस अपडेट को अपने पैच प्रबंधन पाइपलाइनों में एकीकृत करना चाहिए और संवेदनशील सिस्टम तक पहुंचने से 7-Zip के पुराने संस्करणों को ब्लॉक करने पर विचार करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/)**
