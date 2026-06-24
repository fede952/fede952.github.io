---
title: "Salesforce हमले बढ़े, Icarus ने Klue उल्लंघन के माध्यम से चुराए गए डेटा को लीक किया"
date: "2026-06-24T10:22:11Z"
original_date: "2026-06-23T20:44:09"
lang: "hi"
translationKey: "salesforce-attacks-widen-as-icarus-leaks-stolen-data-via-klue-breach"
author: "NewsBot (Validated by Federico Sella)"
description: "हमलावरों ने Salesforce इंस्टेंस तक पहुंचने के लिए Klue के OAuth टोकन का शोषण किया; Icarus द्वारा चुराए गए डेटा को लीक करने के साथ और पीड़ित सामने आए।"
original_url: "https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data"
source: "Dark Reading"
severity: "High"
target: "Klue OAuth टोकन के माध्यम से Salesforce इंस्टेंस"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

हमलावरों ने Salesforce इंस्टेंस तक पहुंचने के लिए Klue के OAuth टोकन का शोषण किया; Icarus द्वारा चुराए गए डेटा को लीक करने के साथ और पीड़ित सामने आए।

{{< cyber-report severity="High" source="Dark Reading" target="Klue OAuth टोकन के माध्यम से Salesforce इंस्टेंस" >}}

Salesforce के खिलाफ चल रहे हमलों का दायरा बढ़ गया है क्योंकि Icarus के नाम से ट्रैक किए जाने वाले खतरे वाले अभिनेताओं ने कई पीड़ितों से चुराए गए डेटा को लीक कर दिया है। हमलावरों ने शुरू में एप्लिकेशन विक्रेता Klue का उल्लंघन किया और ग्राहकों के Salesforce वातावरण में अनधिकृत पहुंच प्राप्त करने के लिए इसके OAuth टोकन का लाभ उठाया।

{{< ad-banner >}}

Dark Reading के अनुसार, प्रारंभिक खुलासे के बाद नए पीड़ित सामने आए हैं, जो दर्शाता है कि हमला अभियान पहले की समझ से अधिक व्यापक है। OAuth टोकन के उपयोग ने हमलावरों को पारंपरिक प्रमाणीकरण नियंत्रणों को बायपास करने और सामान्य अलर्ट को ट्रिगर किए बिना सीधे Salesforce डेटा तक पहुंचने की अनुमति दी।

Klue जैसे तीसरे पक्ष के विक्रेताओं के साथ Salesforce एकीकरण का उपयोग करने वाले संगठनों को OAuth टोकन अनुमतियों का ऑडिट करने और असामान्य पहुंच पैटर्न की निगरानी करने का आग्रह किया जाता है। Icarus समूह ने चुराए गए डेटा को लीक करना शुरू कर दिया है, जिससे प्रभावित कंपनियों के लिए प्रतिक्रिया देने की तात्कालिकता बढ़ गई है।

{{< netrunner-insight >}}

यह हमला SaaS पारिस्थितिकी तंत्र में OAuth टोकन दुरुपयोग के जोखिम को रेखांकित करता है। SOC विश्लेषकों को एकीकृत तीसरे पक्ष के ऐप्स से असामान्य API कॉल और टोकन उपयोग की निगरानी को प्राथमिकता देनी चाहिए। DevSecOps टीमों को सख्त टोकन जीवनचक्र प्रबंधन लागू करना चाहिए और विस्फोट त्रिज्या को सीमित करने के लिए जस्ट-इन-टाइम अनुमतियां लागू करनी चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख Dark Reading पर पढ़ें ›](https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data)**
