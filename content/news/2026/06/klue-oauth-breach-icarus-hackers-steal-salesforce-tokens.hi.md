---
title: "Klue OAuth उल्लंघन: Icarus हैकर्स ने Salesforce टोकन चुराए"
date: "2026-06-20T09:59:52Z"
original_date: "2026-06-19T22:31:04"
lang: "hi"
translationKey: "klue-oauth-breach-icarus-hackers-steal-salesforce-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Klue ने Salesforce एकीकरण को प्रभावित करने वाली OAuth टोकन चोरी की पुष्टि की; Icarus जबरन वसूली समूह ने जिम्मेदारी ली और पीड़ितों की सूची बढ़ रही है।"
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/"
source: "BleepingComputer"
severity: "High"
target: "Klue बाजार खुफिया प्लेटफॉर्म"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Klue ने Salesforce एकीकरण को प्रभावित करने वाली OAuth टोकन चोरी की पुष्टि की; Icarus जबरन वसूली समूह ने जिम्मेदारी ली और पीड़ितों की सूची बढ़ रही है।

{{< cyber-report severity="High" source="BleepingComputer" target="Klue बाजार खुफिया प्लेटफॉर्म" >}}

बाजार खुफिया प्लेटफॉर्म Klue ने एक सुरक्षा घटना की पुष्टि की है जिसमें खतरा अभिनेताओं ने ग्राहकों के Salesforce वातावरण से जुड़ने के लिए उपयोग किए जाने वाले OAuth टोकन चुरा लिए। नव उभरे 'Icarus' जबरन वसूली समूह द्वारा दावा किए गए इस उल्लंघन के कारण प्रभावित पीड़ितों की सूची बढ़ रही है।

{{< ad-banner >}}

चुराए गए OAuth टोकन हमलावरों को आगे प्रमाणीकरण की आवश्यकता के बिना Salesforce डेटा तक पहुंचने की अनुमति दे सकते हैं, जो Klue ग्राहकों के लिए एक महत्वपूर्ण जोखिम पैदा करता है। यह घटना OAuth टोकन एक्सपोजर के खतरों और मजबूत टोकन जीवनचक्र प्रबंधन की आवश्यकता को उजागर करती है।

जैसे ही Icarus समूह सार्वजनिक रूप से हमले का दावा करता है, Klue के Salesforce एकीकरण का उपयोग करने वाले संगठनों को तुरंत किसी भी संबंधित OAuth टोकन को रद्द और घुमाना चाहिए और अनधिकृत पहुंच के लिए निगरानी करनी चाहिए। उल्लंघन का पूरा दायरा अभी भी जांच के अधीन है।

{{< netrunner-insight >}}

यह घटना संवेदनशील क्रेडेंशियल्स के रूप में OAuth टोकन को सुरक्षित करने के महत्वपूर्ण महत्व को रेखांकित करती है। SOC विश्लेषकों को असामान्य Salesforce API कॉल की निगरानी को प्राथमिकता देनी चाहिए और टोकन समाप्ति नीतियों को लागू करना चाहिए। DevSecOps टीमों को समझौता होने की स्थिति में विस्फोट त्रिज्या को सीमित करने के लिए सख्त टोकन स्कोपिंग और रोटेशन तंत्र लागू करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/)**
