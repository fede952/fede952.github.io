---
title: "Ivanti, Fortinet, SAP, VMware, n8n ने RCE, SQLi, विशेषाधिकार वृद्धि दोषों को पैच किया"
date: "2026-05-19T10:36:29Z"
original_date: "2026-05-18T10:54:05"
lang: "hi"
translationKey: "ivanti-fortinet-sap-vmware-n8n-patch-rce-sqli-privilege-escalation-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "कई विक्रेताओं ने गंभीर कमजोरियों के लिए सुरक्षा फिक्स जारी किए, जिनमें Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) शामिल है, जो सूचना प्रकटीकरण या क्लाइंट-साइड हमलों का कारण बन सकता है।"
original_url: "https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html"
source: "The Hacker News"
severity: "Critical"
target: "Ivanti Xtraction"
cve: "CVE-2026-8043"
cvss: 9.6
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

कई विक्रेताओं ने गंभीर कमजोरियों के लिए सुरक्षा फिक्स जारी किए, जिनमें Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) शामिल है, जो सूचना प्रकटीकरण या क्लाइंट-साइड हमलों का कारण बन सकता है।

{{< cyber-report severity="Critical" source="The Hacker News" target="Ivanti Xtraction" cve="CVE-2026-8043" cvss="9.6" >}}

Ivanti, Fortinet, n8n, SAP और VMware ने कई कमजोरियों को संबोधित करने वाले सुरक्षा पैच जारी किए हैं जिनका उपयोग प्रमाणीकरण बाईपास और मनमाना कोड निष्पादन के लिए किया जा सकता है। सबसे गंभीर दोष Ivanti Xtraction में CVE-2026-8043 है, जिसका CVSS स्कोर 9.6 है, जो फ़ाइल नाम के बाहरी नियंत्रण की अनुमति देता है जिससे सूचना प्रकटीकरण या क्लाइंट-साइड हमले हो सकते हैं।

{{< ad-banner >}}

अन्य विक्रेताओं ने भी उच्च-गंभीरता वाले मुद्दों को संबोधित किया, जिनमें SQL इंजेक्शन और विशेषाधिकार वृद्धि कमजोरियां शामिल हैं। संगठनों से आग्रह किया जाता है कि वे इन दोषों को प्राथमिकता से पैच करें, विशेष रूप से वे जो इंटरनेट पर उजागर हैं, क्योंकि इन्हें पूर्ण सिस्टम समझौते के लिए श्रृंखलाबद्ध किया जा सकता है।

हालांकि अभी तक कोई सक्रिय शोषण रिपोर्ट नहीं किया गया है, लेकिन व्यापक हमले की सतह और उच्च CVSS स्कोर सुरक्षा टीमों से तत्काल ध्यान देने की मांग करते हैं। जोखिमों को कम करने के लिए नियमित भेद्यता स्कैनिंग और पैच प्रबंधन महत्वपूर्ण हैं।

{{< netrunner-insight >}}

SOC विश्लेषकों को इसके गंभीर CVSS स्कोर और क्लाइंट-साइड हमलों की संभावना के कारण Ivanti Xtraction CVE-2026-8043 पैच को प्राथमिकता देनी चाहिए। DevSecOps टीमों को यह सुनिश्चित करना होगा कि सभी प्रभावित सिस्टम अपडेट किए गए हैं और शोषण के किसी भी संकेत के लिए निगरानी करें, क्योंकि फ़ाइल नामों का बाहरी नियंत्रण डेटा निष्कासन या पार्श्व आंदोलन का कारण बन सकता है।

{{< /netrunner-insight >}}

---

**[पूरा लेख The Hacker News पर पढ़ें ›](https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html)**
