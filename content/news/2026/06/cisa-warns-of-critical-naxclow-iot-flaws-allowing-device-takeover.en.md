---
title: "CISA Warns of Critical Naxclow IoT Flaws Allowing Device Takeover"
date: "2026-06-12T10:59:58Z"
original_date: "2026-06-11T12:00:00"
lang: "en"
translationKey: "cisa-warns-of-critical-naxclow-iot-flaws-allowing-device-takeover"
author: "NewsBot (Validated by Federico Sella)"
description: "Multiple vulnerabilities in Naxclow IoT Platform, including CVE-2026-42947, allow device hijacking and credential harvesting. Affects smart doorbells and home hubs."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02"
source: "CISA"
severity: "Critical"
target: "Naxclow IoT Platform devices"
cve: "CVE-2026-42947"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Multiple vulnerabilities in Naxclow IoT Platform, including CVE-2026-42947, allow device hijacking and credential harvesting. Affects smart doorbells and home hubs.

{{< cyber-report severity="Critical" source="CISA" target="Naxclow IoT Platform devices" cve="CVE-2026-42947" cvss="9.8" >}}

CISA has issued an advisory (ICSA-26-162-02) detailing multiple vulnerabilities in the Naxclow IoT Platform, affecting products such as the Smart Doorbell X3, X Smart Home, V720, and ix cam. The most severe flaw, CVE-2026-42947, carries a CVSS score of 9.8 and involves an authorization bypass through a user-controlled key, allowing an attacker to replay a confirm-then-bind sequence to silently reassign a device to an arbitrary account without user interaction.

{{< ad-banner >}}

Additional weaknesses include missing authorization checks, use of hard-coded cryptographic keys, generation of predictable identifiers, and insertion of sensitive information into externally accessible files. Successful exploitation could enable device impersonation, communication interception or manipulation, large-scale credential harvesting, and unauthorized access to affected systems.

The vulnerabilities affect all versions of the listed products, and the devices are deployed worldwide across commercial facilities. Naxclow, headquartered in China, has not yet released patches. Organizations using these devices should immediately implement network segmentation and monitoring to detect anomalous device binding activities.

{{< netrunner-insight >}}

This is a textbook supply-chain IoT nightmare: hardcoded keys, predictable IDs, and a replayable onboarding flow. SOC teams should hunt for unexpected device reassignments in logs and consider isolating Naxclow devices on a separate VLAN until patches arrive. DevSecOps must push for cryptographic device identity and mutual authentication in IoT onboarding.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02)**
