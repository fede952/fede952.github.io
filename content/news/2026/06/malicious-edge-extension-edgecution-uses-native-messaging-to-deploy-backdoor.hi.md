---
title: "दुर्भावनापूर्ण Edge एक्सटेंशन 'Edgecution' बैकडोर तैनात करने के लिए नेटिव मैसेजिंग का उपयोग करता है"
date: "2026-06-25T10:16:09Z"
original_date: "2026-06-24T20:58:22"
lang: "hi"
translationKey: "malicious-edge-extension-edgecution-uses-native-messaging-to-deploy-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "एक दुर्भावनापूर्ण Microsoft Edge एक्सटेंशन जिसका नाम 'Edgecution' है, रैनसमवेयर हमलों में पायथन-आधारित बैकडोर तैनात करने के लिए नेटिव मैसेजिंग के माध्यम से ब्राउज़र सैंडबॉक्स से बच निकलता है।"
original_url: "https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/"
source: "BleepingComputer"
severity: "High"
target: "Microsoft Edge उपयोगकर्ता"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

एक दुर्भावनापूर्ण Microsoft Edge एक्सटेंशन जिसका नाम 'Edgecution' है, रैनसमवेयर हमलों में पायथन-आधारित बैकडोर तैनात करने के लिए नेटिव मैसेजिंग के माध्यम से ब्राउज़र सैंडबॉक्स से बच निकलता है।

{{< cyber-report severity="High" source="BleepingComputer" target="Microsoft Edge उपयोगकर्ता" >}}

एक दुर्भावनापूर्ण Microsoft Edge एक्सटेंशन जिसे 'Edgecution' कहा जाता है, एक रैनसमवेयर हमले में देखा गया है, जो ब्राउज़र के नेटिव मैसेजिंग API का लाभ उठाकर सैंडबॉक्स से बच निकलता है और होस्ट सिस्टम पर मनमाना कोड निष्पादित करता है। यह एक्सटेंशन पायथन-आधारित बैकडोर तैनात करने के लिए एक पुल के रूप में कार्य करता है, जो स्थायी पहुंच और आगे की दुर्भावनापूर्ण गतिविधियों को सक्षम बनाता है।

{{< ad-banner >}}

हमले की श्रृंखला दुष्ट एक्सटेंशन की स्थापना के साथ शुरू होती है, जो फिर ब्राउज़र सैंडबॉक्स के बाहर एक नेटिव एप्लिकेशन के साथ संवाद करने के लिए नेटिव मैसेजिंग का दुरुपयोग करती है। यह तकनीक सामान्य ब्राउज़र सुरक्षा सीमाओं को दरकिनार करती है, जिससे हमलावर को कमांड निष्पादित करने और रैनसमवेयर सहित अतिरिक्त पेलोड छोड़ने की अनुमति मिलती है।

सुरक्षा शोधकर्ताओं ने इस बात पर प्रकाश डाला है कि यह विधि विशेष रूप से कपटपूर्ण है क्योंकि यह एक वैध ब्राउज़र सुविधा का शोषण करती है, जिससे पारंपरिक एंडपॉइंट सुरक्षा समाधानों के लिए पहचान चुनौतीपूर्ण हो जाती है। संगठनों को अनधिकृत ब्राउज़र एक्सटेंशन की निगरानी करने और जहां संभव हो, नेटिव मैसेजिंग अनुमतियों को प्रतिबंधित करने की सलाह दी जाती है।

{{< netrunner-insight >}}

यह हमला ब्राउज़र एक्सटेंशन इंस्टॉलेशन और नेटिव मैसेजिंग गतिविधि की निगरानी के महत्व को रेखांकित करता है। SOC विश्लेषकों को असामान्य एक्सटेंशन व्यवहार और अप्रत्याशित नेटिव होस्ट संचार की तलाश करनी चाहिए, जबकि DevSecOps टीमों को सख्त एक्सटेंशन अनुमति सूची लागू करनी चाहिए और अनावश्यक नेटिव मैसेजिंग होस्ट को अक्षम करना चाहिए।

{{< /netrunner-insight >}}

---

**[पूरा लेख BleepingComputer पर पढ़ें ›](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)**
