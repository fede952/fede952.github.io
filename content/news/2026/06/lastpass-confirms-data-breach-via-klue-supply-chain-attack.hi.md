---
title: "LastPass ने Klue आपूर्ति श्रृंखला हमले के माध्यम से डेटा उल्लंघन की पुष्टि की"
date: "2026-06-24T10:23:36Z"
original_date: "2026-06-23T13:58:25"
lang: "hi"
translationKey: "lastpass-confirms-data-breach-via-klue-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "LastPass ने खुलासा किया कि हमलावरों ने तीसरे पक्ष के ऐप Klue से OAuth टोकन चुराकर अपने Salesforce वातावरण में ग्राहक डेटा तक पहुंच बनाई।"
original_url: "https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "LastPass Salesforce वातावरण"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

LastPass ने खुलासा किया कि हमलावरों ने तीसरे पक्ष के ऐप Klue से OAuth टोकन चुराकर अपने Salesforce वातावरण में ग्राहक डेटा तक पहुंच बनाई।

{{< cyber-report severity="High" source="BleepingComputer" target="LastPass Salesforce वातावरण" >}}

LastPass ने पुष्टि की है कि हैकर्स ने इस महीने की शुरुआत में Klue आपूर्ति श्रृंखला हमले में कंपनी के OAuth टोकन चुराने के बाद अपने Salesforce वातावरण से ग्राहक डेटा तक पहुंच बनाई। 23 जून, 2026 को खुलासा किया गया यह उल्लंघन तीसरे पक्ष के एकीकरण और टोकन चोरी के जोखिमों को उजागर करता है।

{{< ad-banner >}}

हमलावरों ने तीसरे पक्ष के एप्लिकेशन Klue से समझौता किए गए OAuth टोकन का उपयोग करके LastPass के Salesforce इंस्टेंस तक अनधिकृत पहुंच प्राप्त की। इस आपूर्ति श्रृंखला हमले ने खतरे वाले अभिनेताओं को सामान्य प्रमाणीकरण अलर्ट को ट्रिगर किए बिना ग्राहक डेटा निकालने की अनुमति दी।

LastPass प्रभावित ग्राहकों को सूचित कर रहा है और समझौता किए गए टोकन को रद्द कर दिया है। कंपनी समान घटनाओं को रोकने के लिए अपनी तीसरे पक्ष की पहुंच नीतियों की समीक्षा भी कर रही है। यह उल्लंघन OAuth टोकन उपयोग की निगरानी और एकीकृत सेवाओं के लिए सख्त पहुंच नियंत्रण लागू करने के महत्व को रेखांकित करता है।

{{< netrunner-insight >}}

यह घटना OAuth टोकन दुरुपयोग के माध्यम से आपूर्ति श्रृंखला जोखिम का एक उत्कृष्ट उदाहरण है। SOC विश्लेषकों को असामान्य टोकन उपयोग की निगरानी को प्राथमिकता देनी चाहिए और टोकन समाप्ति नीतियों को लागू करना चाहिए। DevSecOps टीमों को तीसरे पक्ष के एकीकरण के लिए न्यूनतम-विशेषाधिकार पहुंच लागू करनी चाहिए और विस्फोट त्रिज्या को कम करने के लिए अल्पकालिक टोकन का उपयोग करने पर विचार करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/)**
