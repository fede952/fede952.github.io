---
title: "Sandworm-Linked UAC-0145 Uses Fake Job Interviews to Push Malicious VPN"
date: "2026-08-15T07:23:49Z"
original_date: "2026-08-11T18:36:47"
lang: "en"
translationKey: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
slug: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-UA warns of Russian nation-state threat actors targeting Ukrainian IT workers via fake job interviews, delivering a VPN that can execute commands."
original_url: "https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html"
source: "The Hacker News"
severity: "High"
target: "Ukrainian IT workers"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-UA warns of Russian nation-state threat actors targeting Ukrainian IT workers via fake job interviews, delivering a VPN that can execute commands.

{{< cyber-report severity="High" source="The Hacker News" target="Ukrainian IT workers" >}}

CERT-UA has disclosed a new social engineering campaign attributed to the threat cluster UAC-0145, a subgroup of the Russian nation-state group Sandworm (APT44). The campaign targets IT workers in Ukraine by impersonating recruiters and luring victims into fake job interviews.

{{< ad-banner >}}

During the interview process, victims are tricked into installing a VPN application that is actually malware capable of executing arbitrary commands on the compromised system. This technique leverages the trust associated with job recruitment to bypass user defenses.

The activity underscores the ongoing cyber threat from Russian state-sponsored actors against Ukrainian organizations, particularly those in the IT sector. CERT-UA's attribution to UAC-0145 highlights the sophisticated and persistent nature of these attacks.

{{< netrunner-insight >}}

This campaign demonstrates the effectiveness of social engineering in delivering malware, even to security-conscious IT professionals. SOC analysts should educate users about such recruitment-based lures and monitor for unusual VPN installations or command execution. DevSecOps teams should enforce application allowlisting and restrict execution of unsigned binaries to mitigate such threats.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html)**
