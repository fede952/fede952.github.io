---
title: "SPID-Themed Phishing Campaign Targets Italian Users' Credentials"
date: "2026-08-17T07:50:54Z"
original_date: "2026-08-03T11:05:05"
lang: "en"
translationKey: "spid-themed-phishing-campaign-targets-italian-users-credentials"
slug: "spid-themed-phishing-campaign-targets-italian-users-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-AGID warns of a new phishing campaign abusing SPID and AgID branding to steal personal and banking data via domains containing 'spid' and 'gov'."
original_url: "https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/"
source: "CERT-AgID"
severity: "Medium"
target: "Italian SPID users"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-AGID warns of a new phishing campaign abusing SPID and AgID branding to steal personal and banking data via domains containing 'spid' and 'gov'.

{{< cyber-report severity="Medium" source="CERT-AgID" target="Italian SPID users" >}}

CERT-AGID has identified an ongoing phishing campaign that abuses the SPID (Sistema Pubblico di Identità Digitale) theme to fraudulently acquire personal and banking information from Italian users. The campaign leverages the official names and logos of AgID and SPID to enhance its credibility, making it particularly deceptive.

{{< ad-banner >}}

The attackers are using multiple domains that incorporate the terms 'spid' and 'gov' in their names, a tactic designed to trick users into believing they are interacting with legitimate government services. This approach exploits the trust users place in official-looking domains and branding.

While the exact attack vector (e.g., email, SMS) is not specified in the advisory, the campaign's goal is clear: to harvest sensitive data. Users are advised to verify the authenticity of any communication requesting personal or banking information and to report suspicious messages to the appropriate authorities.

{{< netrunner-insight >}}

For SOC analysts, this campaign underscores the importance of monitoring for lookalike domains that combine trusted brand terms with 'gov' or similar TLDs. Implement email filtering rules that flag messages containing such domains, and educate users to verify URLs before clicking. DevSecOps teams should consider integrating domain reputation feeds into their security stack to automatically block these phishing domains.

{{< /netrunner-insight >}}

---

**[Read full article on CERT-AgID ›](https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/)**
