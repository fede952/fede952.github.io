---
title: "WriteOut: राइटर AI में क्रिटिकल सेशन आइसोलेशन खामी से टोकन लीक होने का खतरा"
date: "2026-07-08T09:23:55Z"
original_date: "2026-07-07T13:27:09"
lang: "hi"
translationKey: "writeout-critical-session-isolation-flaw-in-writer-ai-could-leak-tokens-across-tenants"
slug: "writeout-critical-session-isolation-flaw-in-writer-ai-could-leak-tokens-across-tenants"
author: "NewsBot (Validated by Federico Sella)"
description: "राइटर AI में एक-क्लिक वाली कमजोरी, जिसे WriteOut कोडनेम दिया गया, क्रॉस-टेनेंट सेशन टोकन लीक का कारण बन सकती है। यह खामी अब पैच कर दी गई है।"
original_url: "https://thehackernews.com/2026/07/writer-ai-flaw-could-let-agent-previews.html"
source: "The Hacker News"
severity: "Critical"
target: "Writer AI एंटरप्राइज प्लेटफॉर्म"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

राइटर AI में एक-क्लिक वाली कमजोरी, जिसे WriteOut कोडनेम दिया गया, क्रॉस-टेनेंट सेशन टोकन लीक का कारण बन सकती है। यह खामी अब पैच कर दी गई है।

{{< cyber-report severity="Critical" source="The Hacker News" target="Writer AI एंटरप्राइज प्लेटफॉर्म" >}}

सैंड सिक्योरिटी के साइबर सुरक्षा शोधकर्ताओं ने Writer, एक एंटरप्राइज जनरेटिव AI प्लेटफॉर्म, में एक क्रिटिकल सेशन आइसोलेशन कमजोरी का खुलासा किया है। WriteOut नामक इस खामी से हमलावर एक क्लिक में टेनेंट के बीच सेशन टोकन लीक कर सकता है, जिससे क्रॉस-टेनेंट समझौता हो सकता है।

{{< ad-banner >}}

यह कमजोरी एजेंट प्रीव्यू फीचर में अनुचित सेशन आइसोलेशन के कारण उत्पन्न होती है, जिससे बाहरी व्यक्ति बिना एक्सेस के किसी भी Writer AI टेनेंट पर पूर्ण नियंत्रण प्राप्त कर सकता है। Writer ने इस समस्या को पैच कर दिया है, लेकिन यह खोज मल्टी-टेनेंट AI प्लेटफॉर्म के जोखिमों को उजागर करती है।

Writer AI का उपयोग करने वाले संगठनों को सुनिश्चित करना चाहिए कि नवीनतम पैच लागू किए गए हैं और सेशन प्रबंधन कॉन्फ़िगरेशन की समीक्षा करें। WriteOut कमजोरी क्लाउड-आधारित AI सेवाओं में टेनेंट आइसोलेशन को प्राथमिकता देने की याद दिलाती है।

{{< netrunner-insight >}}

SOC विश्लेषकों के लिए: Writer AI लॉग में असामान्य सेशन टोकन उपयोग और क्रॉस-टेनेंट एक्सेस पैटर्न की निगरानी करें। DevSecOps टीमों को सख्त सेशन आइसोलेशन लागू करना चाहिए और मल्टी-टेनेंट AI डिप्लॉयमेंट में अतिरिक्त टेनेंट बाउंड्री जांच पर विचार करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/07/writer-ai-flaw-could-let-agent-previews.html)**
