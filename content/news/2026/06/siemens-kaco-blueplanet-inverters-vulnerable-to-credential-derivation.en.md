---
title: "Siemens KACO Blueplanet Inverters Vulnerable to Credential Derivation"
date: "2026-06-10T10:51:15Z"
original_date: "2026-06-09T12:00:00"
lang: "en"
translationKey: "siemens-kaco-blueplanet-inverters-vulnerable-to-credential-derivation"
author: "NewsBot (Validated by Federico Sella)"
description: "Multiple vulnerabilities in KACO blueplanet inverters allow attackers to derive credentials from serial numbers, gaining unauthorized access. Siemens recommends updates."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02"
source: "CISA"
severity: "High"
target: "Siemens KACO Blueplanet Inverters"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Multiple vulnerabilities in KACO blueplanet inverters allow attackers to derive credentials from serial numbers, gaining unauthorized access. Siemens recommends updates.

{{< cyber-report severity="High" source="CISA" target="Siemens KACO Blueplanet Inverters" >}}

CISA has released an advisory (ICSA-26-160-02) detailing multiple vulnerabilities in Siemens KACO blueplanet inverters. These flaws could allow an attacker to derive credentials from a device's serial number and misuse them to gain unauthorized access to the inverter.

{{< ad-banner >}}

The advisory covers a wide range of affected models, including blueplanet 100 NX3 M8, 100 TL3 GEN2, 105 TL3, and many others, with versions listed as all/* or specific firmware versions below 6.1.4.9. KACO new energy GmbH has released updates for some products and is preparing fixes for others, recommending countermeasures where patches are not yet available.

No CVE identifiers or CVSS scores are provided in the advisory. The vulnerabilities are considered serious due to the potential for remote exploitation leading to unauthorized device access, which could impact solar energy infrastructure.

{{< netrunner-insight >}}

For SOC analysts and DevSecOps engineers, this advisory underscores the risk of hardcoded or derivable credentials in IoT/OT devices. Immediately inventory affected KACO inverters and apply firmware updates where available. For unpatched units, implement network segmentation and monitor for anomalous access attempts as interim mitigations.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02)**
