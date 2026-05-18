---
title: "MiniPlasma विंडोज 0-डे पूरी तरह से पैच किए गए सिस्टम पर SYSTEM विशेषाधिकार वृद्धि सक्षम करता है"
date: "2026-05-18T11:01:35Z"
original_date: "2026-05-18T08:57:34"
lang: "hi"
translationKey: "miniplasma-windows-0-day-enables-system-privilege-escalation-on-fully-patched-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "सुरक्षा शोधकर्ता Chaotic Eclipse ने MiniPlasma के लिए PoC जारी किया, जो Windows Cloud Files Mini Filter Driver (cldflt.sys) में एक शून्य-दिवस है जो पूरी तरह से पैच किए गए सिस्टम पर SYSTEM विशेषाधिकार प्रदान करता है।"
original_url: "https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html"
source: "The Hacker News"
severity: "High"
target: "Windows Cloud Files Mini Filter Driver (cldflt.sys)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

सुरक्षा शोधकर्ता Chaotic Eclipse ने MiniPlasma के लिए PoC जारी किया, जो Windows Cloud Files Mini Filter Driver (cldflt.sys) में एक शून्य-दिवस है जो पूरी तरह से पैच किए गए सिस्टम पर SYSTEM विशेषाधिकार प्रदान करता है।

{{< cyber-report severity="High" source="The Hacker News" target="Windows Cloud Files Mini Filter Driver (cldflt.sys)" >}}

Chaotic Eclipse, हाल ही में खुलासा किए गए Windows दोषों YellowKey और GreenPlasma के पीछे सुरक्षा शोधकर्ता, ने Windows विशेषाधिकार वृद्धि शून्य-दिवस दोष के लिए एक प्रूफ-ऑफ-कॉन्सेप्ट (PoC) जारी किया है जो हमलावरों को पूरी तरह से पैच किए गए Windows सिस्टम पर SYSTEM विशेषाधिकार प्रदान करता है। MiniPlasma कोडनेम वाली यह भेद्यता "cldflt.sys" को प्रभावित करती है, जो Windows Cloud Files Mini Filter Driver को संदर्भित करता है।

{{< ad-banner >}}

यह दोष एक हमलावर को सीमित उपयोगकर्ता पहुंच के साथ SYSTEM तक विशेषाधिकार बढ़ाने की अनुमति देता है, जिससे संभावित रूप से पूर्ण सिस्टम समझौता हो सकता है। शून्य-दिवस होने के कारण, वर्तमान में कोई आधिकारिक पैच उपलब्ध नहीं है, जिससे पूरी तरह से पैच किए गए सिस्टम PoC के हथियार बनने पर शोषण के लिए असुरक्षित रह जाते हैं।

संगठनों को cldflt.sys ड्राइवर से असामान्य व्यवहार की निगरानी करनी चाहिए और अतिरिक्त सख्तीकरण उपायों पर विचार करना चाहिए, जैसे Cloud Files सुविधा तक पहुंच को प्रतिबंधित करना या पैच जारी होने तक अस्थायी शमन लागू करना।

{{< netrunner-insight >}}

SOC विश्लेषकों को cldflt.sys को लक्षित करने वाले शोषण प्रयासों की निगरानी को प्राथमिकता देनी चाहिए, क्योंकि PoC हमलावरों के लिए बाधा को कम करता है। DevSecOps टीमों को अपने Windows इमेज सख्तीकरण की समीक्षा करनी चाहिए और यदि आवश्यक नहीं है तो Cloud Files Mini Filter Driver को अक्षम करने पर विचार करना चाहिए, जबकि Microsoft से आधिकारिक सुधार की प्रतीक्षा करनी चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)**
