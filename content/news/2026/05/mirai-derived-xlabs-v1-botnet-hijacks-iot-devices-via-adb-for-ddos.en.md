---
title: "Mirai-Derived xlabs_v1 Botnet Hijacks IoT Devices via ADB for DDoS"
date: "2026-05-07T09:27:29Z"
original_date: "2026-05-06T20:21:00"
lang: "en"
translationKey: "mirai-derived-xlabs-v1-botnet-hijacks-iot-devices-via-adb-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "Researchers uncover xlabs_v1, a new Mirai-based botnet exploiting exposed Android Debug Bridge ports to recruit IoT devices into a DDoS network."
original_url: "https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html"
source: "The Hacker News"
severity: "High"
target: "IoT devices with exposed ADB"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Researchers uncover xlabs_v1, a new Mirai-based botnet exploiting exposed Android Debug Bridge ports to recruit IoT devices into a DDoS network.

{{< cyber-report severity="High" source="The Hacker News" target="IoT devices with exposed ADB" >}}

Cybersecurity researchers have identified a new Mirai-derived botnet, self-identified as xlabs_v1, that targets internet-exposed devices running Android Debug Bridge (ADB). The botnet aims to enlist compromised devices into a network capable of launching distributed denial-of-service (DDoS) attacks.

{{< ad-banner >}}

The discovery was made by Hunt.io after they identified an exposed directory on a server hosted in the Netherlands. The malware exploits ADB, a command-line tool used for debugging Android devices, which is often left exposed on IoT devices, allowing remote attackers to gain unauthorized access.

This campaign highlights the ongoing threat of Mirai variants targeting poorly secured IoT devices. Organizations are advised to disable ADB on production devices and restrict network access to prevent such hijacking.

{{< netrunner-insight >}}

For SOC analysts, monitor for unexpected ADB connections from external IPs. DevSecOps teams should ensure ADB is disabled in production builds and that IoT devices are segmented from critical networks to mitigate this botnet's reach.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html)**
