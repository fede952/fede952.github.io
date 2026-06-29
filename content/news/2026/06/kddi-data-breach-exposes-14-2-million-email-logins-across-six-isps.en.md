---
title: "KDDI data breach exposes 14.2 million email logins across six ISPs"
date: "2026-06-29T11:56:07Z"
original_date: "2026-06-28T14:13:46"
lang: "en"
translationKey: "kddi-data-breach-exposes-14-2-million-email-logins-across-six-isps"
author: "NewsBot (Validated by Federico Sella)"
description: "Japanese telecom KDDI discloses breach of email system affecting five other ISPs, compromising up to 14.2 million user credentials."
original_url: "https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/"
source: "BleepingComputer"
severity: "High"
target: "Japanese ISP email systems"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Japanese telecom KDDI discloses breach of email system affecting five other ISPs, compromising up to 14.2 million user credentials.

{{< cyber-report severity="High" source="BleepingComputer" target="Japanese ISP email systems" >}}

Japanese telecommunications operator KDDI Corporation disclosed a data breach where threat actors gained access to one of its email systems used by five other internet service providers (ISPs) in the country. The breach potentially exposed up to 14.2 million email logins, impacting a significant number of users across multiple providers.

{{< ad-banner >}}

The compromised system is part of KDDI's email infrastructure, which serves as a backend for several ISPs. While the exact method of intrusion has not been detailed, the incident underscores the risks inherent in shared service provider architectures, where a single point of failure can cascade across multiple organizations.

KDDI has notified affected ISPs and is working to contain the breach. Users are advised to change passwords and enable multi-factor authentication where available. The incident highlights the need for robust segmentation and monitoring of shared infrastructure components.

{{< netrunner-insight >}}

This breach is a textbook example of supply chain risk in ISP ecosystems. SOC analysts should prioritize monitoring for lateral movement from email systems to other critical assets, while DevSecOps teams must enforce strict network segmentation and least-privilege access for shared backend services. Expect credential stuffing attacks targeting these exposed accounts in the coming weeks.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/)**
