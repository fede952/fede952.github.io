---
title: "Popa Botnet Tied to Israeli Firm Alarum Technologies"
date: "2026-07-13T10:19:43Z"
original_date: "2026-06-18T17:37:58"
lang: "en"
translationKey: "popa-botnet-tied-to-israeli-firm-alarum-technologies"
slug: "popa-botnet-tied-to-israeli-firm-alarum-technologies"
author: "NewsBot (Validated by Federico Sella)"
description: "Researchers link the Android-based Popa botnet to NetNut, a residential proxy service owned by publicly-traded Alarum Technologies, used for ad fraud and account takeovers."
original_url: "https://krebsonsecurity.com/2026/06/popa-botnet-linked-to-publicly-traded-israeli-firm/"
source: "Krebs on Security"
severity: "High"
target: "Android TV boxes"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Researchers link the Android-based Popa botnet to NetNut, a residential proxy service owned by publicly-traded Alarum Technologies, used for ad fraud and account takeovers.

{{< cyber-report severity="High" source="Krebs on Security" target="Android TV boxes" >}}

For the past four years, the Popa botnet has infected millions of Android-based TV boxes, using them to relay malicious traffic for advertising fraud, account takeovers, and data scraping. The botnet's infrastructure relies on residential proxies to obfuscate its activities.

{{< ad-banner >}}

This week, multiple security firms concluded that Popa is linked to NetNut, a residential proxy provider operated by Alarum Technologies Ltd, a publicly-traded Israeli company. The connection suggests a commercial service may have been knowingly or unknowingly leveraged for cybercriminal operations.

The scale of the botnet—affecting millions of devices—highlights the growing threat of IoT and Android-based botnets. The involvement of a publicly-traded firm raises questions about corporate responsibility and oversight in the proxy service industry.

{{< netrunner-insight >}}

SOC analysts should monitor for traffic from residential proxy IP ranges associated with NetNut, as they may indicate Popa botnet activity. DevSecOps teams should ensure IoT devices are segmented and regularly updated to prevent similar infections. This case underscores the need for due diligence when integrating third-party proxy services into security architectures.

{{< /netrunner-insight >}}

---

**[Read full article on Krebs on Security ›](https://krebsonsecurity.com/2026/06/popa-botnet-linked-to-publicly-traded-israeli-firm/)**
