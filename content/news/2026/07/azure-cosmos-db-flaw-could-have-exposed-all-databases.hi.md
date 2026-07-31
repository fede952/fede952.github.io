---
title: "Azure Cosmos DB में खोजा गया दोष सभी डेटाबेस को उजागर कर सकता था"
date: "2026-07-31T09:37:51Z"
original_date: "2026-07-30T13:34:09"
lang: "hi"
translationKey: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
slug: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
author: "NewsBot (Validated by Federico Sella)"
description: "Azure Cosmos DB में एक पैच किया गया भेद्यता सैंडबॉक्स से बचने और क्रॉस-टेनेंट डेटाबेस एक्सेस की अनुमति देता था, जिसे Wiz ने CosmosEscape के रूप में खोजा।"
original_url: "https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html"
source: "The Hacker News"
severity: "High"
target: "Azure Cosmos DB"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Azure Cosmos DB में एक पैच किया गया भेद्यता सैंडबॉक्स से बचने और क्रॉस-टेनेंट डेटाबेस एक्सेस की अनुमति देता था, जिसे Wiz ने CosmosEscape के रूप में खोजा।

{{< cyber-report severity="High" source="The Hacker News" target="Azure Cosmos DB" >}}

Azure Cosmos DB में एक अब-पैच किया गया भेद्यता एक हमलावर को सेवा के Gremlin क्वेरी सैंडबॉक्स से बचने और ग्राहक टेनेंट्स में डेटाबेस तक पूर्ण पढ़ने और लिखने की पहुंच प्राप्त करने की अनुमति दे सकता था। यह दोष सुरक्षा फर्म Wiz द्वारा खोजा गया था, जिसने शोषण श्रृंखला को 'CosmosEscape' नाम दिया।

{{< ad-banner >}}

हमले की श्रृंखला हमलावर द्वारा नियंत्रित Gremlin डेटाबेस के खिलाफ एक क्राफ्टेड क्वेरी के साथ शुरू हुई। वहां से, हमलावर अंतर्निहित बुनियादी ढांचे पर कोड निष्पादन प्राप्त कर सकता था, संभावित रूप से टेनेंट्स के बीच अलगाव से समझौता कर सकता था।

जबकि Microsoft ने तब से इस मुद्दे को पैच कर दिया है, यह घटना क्लाउड डेटाबेस सेवाओं में टेनेंट अलगाव के महत्वपूर्ण महत्व को रेखांकित करती है। Azure Cosmos DB का उपयोग करने वाले संगठनों को अपने सुरक्षा कॉन्फ़िगरेशन की समीक्षा करनी चाहिए और किसी भी असामान्य गतिविधि की निगरानी करनी चाहिए।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए, यह असामान्य Gremlin क्वेरी और असामान्य डेटाबेस एक्सेस पैटर्न की निगरानी की आवश्यकता पर प्रकाश डालता है। DevSecOps टीमों को यह सुनिश्चित करना चाहिए कि क्लाउड डेटाबेस सेवाएं न्यूनतम विशेषाधिकार के सिद्धांत के साथ कॉन्फ़िगर की गई हैं और किसी भी सैंडबॉक्सिंग तंत्र का नियमित रूप से ऑडिट किया जाता है। भले ही यह पैच किया गया है, समान दोष अन्य प्रबंधित सेवाओं में मौजूद हो सकते हैं, इसलिए सक्रिय खतरे की खोज आवश्यक है।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html)**
