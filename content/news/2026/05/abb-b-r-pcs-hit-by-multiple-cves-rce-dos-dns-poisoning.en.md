---
title: "ABB B&R PCs Hit by Multiple CVEs: RCE, DoS, DNS Poisoning"
date: "2026-05-22T10:21:58Z"
original_date: "2026-05-21T12:00:00"
lang: "en"
translationKey: "abb-b-r-pcs-hit-by-multiple-cves-rce-dos-dns-poisoning"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warns of vulnerabilities in ABB B&R industrial PCs. An update is available. Attackers can achieve remote code execution, DoS, DNS cache poisoning, or data theft."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02"
source: "CISA"
severity: "High"
target: "ABB B&R industrial PCs"
cve: "CVE-2023-45229"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warns of vulnerabilities in ABB B&R industrial PCs. An update is available. Attackers can achieve remote code execution, DoS, DNS cache poisoning, or data theft.

{{< cyber-report severity="High" source="CISA" target="ABB B&R industrial PCs" cve="CVE-2023-45229" >}}

ABB has disclosed vulnerabilities affecting multiple B&R industrial PC product lines, including APC4100, APC910, C80, MPC3100, PPC1200, PPC900, and APC2200. The flaws, tracked as CVE-2023-45229 through CVE-2023-45237, allow network-based attackers to execute remote code, launch denial-of-service attacks, poison DNS caches, or extract sensitive information.

{{< ad-banner >}}

The advisory lists affected versions for each product, with updates available to remediate the issues. For example, APC4100 versions below 1.09 are vulnerable, while version 1.09 is patched. Similarly, APC910 versions up to and including 1.25 are affected. ABB recommends upgrading to the latest firmware versions immediately.

Given the industrial control system (ICS) context, these vulnerabilities pose significant risks to operational technology environments. Organizations using affected ABB B&R PCs should prioritize patching, especially if the devices are exposed to untrusted networks.

{{< netrunner-insight >}}

For SOC analysts, monitor network traffic for anomalous DNS queries or unexpected connections from B&R PCs. DevSecOps teams should inventory all affected devices and apply the firmware updates as soon as possible, as these CVEs enable remote code execution without authentication. Consider segmenting ICS networks to limit exposure.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02)**
