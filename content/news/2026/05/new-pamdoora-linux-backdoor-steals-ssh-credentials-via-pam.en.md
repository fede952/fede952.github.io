---
title: "New PamDOORa Linux Backdoor Steals SSH Credentials via PAM"
date: "2026-05-09T08:29:08Z"
original_date: "2026-05-08T08:41:00"
lang: "en"
translationKey: "new-pamdoora-linux-backdoor-steals-ssh-credentials-via-pam"
author: "NewsBot (Validated by Federico Sella)"
description: "A new Linux backdoor named PamDOORa, sold on a Russian cybercrime forum for $1,600, uses PAM modules to provide persistent SSH access with a magic password and TCP port combination."
original_url: "https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html"
source: "The Hacker News"
severity: "High"
target: "Linux SSH servers"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A new Linux backdoor named PamDOORa, sold on a Russian cybercrime forum for $1,600, uses PAM modules to provide persistent SSH access with a magic password and TCP port combination.

{{< cyber-report severity="High" source="The Hacker News" target="Linux SSH servers" >}}

Cybersecurity researchers have uncovered a new Linux backdoor called PamDOORa, advertised on the Rehub Russian cybercrime forum for $1,600 by a threat actor known as 'darkworm'. The backdoor is designed as a Pluggable Authentication Module (PAM)-based post-exploitation toolkit, enabling persistent SSH access through a combination of a magic password and a specific TCP port.

{{< ad-banner >}}

PamDOORa operates by intercepting SSH authentication via malicious PAM modules, allowing attackers to bypass normal credentials and gain unauthorized access. The use of PAM modules makes the backdoor stealthy, as it integrates into the standard authentication flow of the Linux system.

The sale of such tools on cybercrime forums highlights the ongoing commoditization of sophisticated attack tools. Organizations are advised to monitor for unusual SSH authentication patterns and ensure PAM configurations are audited regularly.

{{< netrunner-insight >}}

For SOC analysts, detecting PamDOORa requires monitoring for unexpected SSH connections on non-standard ports and correlating with PAM module changes. DevSecOps teams should enforce strict PAM configuration management and consider file integrity monitoring for /etc/pam.d/ and related libraries. This backdoor underscores the importance of treating PAM as a critical security boundary.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html)**
