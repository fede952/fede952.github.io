---
title: "OpenSSL HollowByte दोष 11-बाइट TLS अनुरोधों से मेमोरी फ्रीज करता है"
date: "2026-07-18T08:44:53Z"
original_date: "2026-07-17T20:20:53"
lang: "hi"
translationKey: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
slug: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
author: "NewsBot (Validated by Federico Sella)"
description: "OpenSSL में एक डिनायल-ऑफ-सर्विस बग, जिसे HollowByte नाम दिया गया है, हमलावरों को छोटे TLS अनुरोधों का उपयोग करके सर्वर मेमोरी फ्रीज करने देता है। Okta की Red Team ने इसकी रिपोर्ट की; बिना CVE के फिक्स जारी किया गया।"
original_url: "https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html"
source: "The Hacker News"
severity: "High"
target: "glibc सिस्टम पर OpenSSL सर्वर"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

OpenSSL में एक डिनायल-ऑफ-सर्विस बग, जिसे HollowByte नाम दिया गया है, हमलावरों को छोटे TLS अनुरोधों का उपयोग करके सर्वर मेमोरी फ्रीज करने देता है। Okta की Red Team ने इसकी रिपोर्ट की; बिना CVE के फिक्स जारी किया गया।

{{< cyber-report severity="High" source="The Hacker News" target="glibc सिस्टम पर OpenSSL सर्वर" >}}

OpenSSL में एक नई खोजी गई डिनायल-ऑफ-सर्विस कमजोरी, जिसे Okta की Red Team ने HollowByte नाम दिया है, एक हमलावर को केवल 11 बाइट्स TLS हैंडशेक डेटा से सर्वर मेमोरी खत्म करने की अनुमति देती है। यह दोष एक अप्रकाशित OpenSSL सर्वर को एक संदेश के लिए 131 KB तक मेमोरी आवंटित करने का कारण बनता है जो कभी नहीं आता, और glibc का उपयोग करने वाले सिस्टम पर, वह मेमोरी प्रक्रिया के पुनरारंभ होने तक मुक्त नहीं होती।

{{< ad-banner >}}

OpenSSL ने जून 2026 में बिना CVE पहचानकर्ता निर्दिष्ट किए, बिना सलाह जारी किए, या चेंजलॉग में परिवर्तन नोट किए बिना फिक्स जारी किया। Okta की Red Team, जिसने बग की खोज की और रिपोर्ट किया, ने फिक्स जारी होने के बाद विवरण प्रकाशित किए। यह कमजोरी glibc-आधारित सिस्टम पर चलने वाले OpenSSL सर्वरों को प्रभावित करती है, जिससे वे मेमोरी थकावट हमलों के लिए संवेदनशील हो जाते हैं।

जबकि हमले के लिए केवल 11 बाइट्स का एक TLS ClientHello आवश्यक है, प्रभाव उन वातावरणों में गंभीर हो सकता है जहां OpenSSL प्रक्रियाएं लंबे समय तक चलती हैं और कई समवर्ती कनेक्शनों को संभालती हैं। glibc पर OpenSSL चलाने वाले संगठनों को संभावित डिनायल-ऑफ-सर्विस स्थितियों को रोकने के लिए जून 2026 अपडेट लागू करने को प्राथमिकता देनी चाहिए।

{{< netrunner-insight >}}

यह एक क्लासिक संसाधन थकावट वेक्टर है जो पारंपरिक दर सीमित को बायपास करता है क्योंकि दुर्भावनापूर्ण ट्रैफ़िक सामान्य TLS हैंडशेक जैसा दिखता है। SOC विश्लेषकों को OpenSSL सर्वरों पर मेमोरी उपयोग में अचानक वृद्धि की निगरानी करनी चाहिए, और DevSecOps टीमों को यह सत्यापित करना चाहिए कि जून 2026 का OpenSSL अपडेट बिना CVE के भी तैनात किया गया है। CVE की कमी परिचालन जोखिम को कम नहीं करती—इसे उच्च-प्राथमिकता वाले पैच के रूप में मानें।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html)**
