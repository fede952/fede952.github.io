---
title: "GoldenEyeDog उपसमूह DigiCert उल्लंघन और कोड-हस्ताक्षर चोरी से जुड़ा"
date: "2026-07-18T08:46:42Z"
original_date: "2026-07-17T16:39:16"
lang: "hi"
translationKey: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
slug: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "शोधकर्ता अप्रैल 2026 की DigiCert घटना का श्रेय CylindricalCanine को देते हैं, जो चीनी साइबर अपराध समूह GoldenEyeDog का एक उपसमूह है, जो जुआ और गेमिंग क्षेत्रों को लक्षित करने के लिए जाना जाता है।"
original_url: "https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html"
source: "The Hacker News"
severity: "High"
target: "DigiCert कोड-हस्ताक्षर बुनियादी ढांचा"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

शोधकर्ता अप्रैल 2026 की DigiCert घटना का श्रेय CylindricalCanine को देते हैं, जो चीनी साइबर अपराध समूह GoldenEyeDog का एक उपसमूह है, जो जुआ और गेमिंग क्षेत्रों को लक्षित करने के लिए जाना जाता है।

{{< cyber-report severity="High" source="The Hacker News" target="DigiCert कोड-हस्ताक्षर बुनियादी ढांचा" >}}

साइबर सुरक्षा शोधकर्ताओं ने अप्रैल 2026 में DigiCert पर हुई सुरक्षा घटना का श्रेय CylindricalCanine नामक खतरा गतिविधि समूह को दिया है। इस समूह को GoldenEyeDog (जिसे APT-Q-27, Dragon Breath और Miuuti Group के नाम से भी जाना जाता है) का उपसमूह बताया गया है, जो एक चीनी साइबर अपराध समूह है जो ऐतिहासिक रूप से जुआ और गेमिंग क्षेत्रों को लक्षित करता है।

{{< ad-banner >}}

इस उल्लंघन में कोड-हस्ताक्षर प्रमाणपत्रों की चोरी शामिल थी, जो खतरा पैदा करने वालों को वैध क्रेडेंशियल्स के साथ दुर्भावनापूर्ण सॉफ़्टवेयर पर हस्ताक्षर करने में सक्षम बना सकता है, जिससे सुरक्षा नियंत्रणों को दरकिनार किया जा सकता है। Expel ने इस घटना के तकनीकी विवरण साझा किए, जो ऑपरेशन की परिष्कृत प्रकृति को उजागर करते हैं।

जो संगठन DigiCert द्वारा जारी प्रमाणपत्रों पर निर्भर हैं, उन्हें अपनी प्रमाणपत्र सूची की समीक्षा करनी चाहिए और किसी भी अनधिकृत उपयोग पर नज़र रखनी चाहिए। यह घटना विश्वसनीय प्रमाणपत्र प्राधिकरणों को लक्षित करने वाले आपूर्ति श्रृंखला हमलों से उत्पन्न जोखिमों को रेखांकित करती है।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए: कोड-हस्ताक्षर विसंगतियों और अप्रत्याशित प्रमाणपत्र उपयोग की निगरानी को प्राथमिकता दें। DevSecOps टीमों को सख्त प्रमाणपत्र जीवनचक्र प्रबंधन लागू करना चाहिए और चोरी से जोखिम को सीमित करने के लिए अल्पकालिक प्रमाणपत्रों पर विचार करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html)**
