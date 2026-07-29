---
title: "'Certighost' Flaw Haunts Microsoft Active Directory Certificates"
date: "2026-07-29T09:36:19Z"
original_date: "2026-07-28T16:38:48"
lang: "en"
translationKey: "certighost-flaw-haunts-microsoft-active-directory-certificates"
slug: "certighost-flaw-haunts-microsoft-active-directory-certificates"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft patched a high-severity vulnerability allowing privilege escalation in Active Directory environments. SOC analysts should prioritize patching."
original_url: "https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates"
source: "Dark Reading"
severity: "High"
target: "Microsoft Active Directory Certificate Services"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft patched a high-severity vulnerability allowing privilege escalation in Active Directory environments. SOC analysts should prioritize patching.

{{< cyber-report severity="High" source="Dark Reading" target="Microsoft Active Directory Certificate Services" >}}

Microsoft has patched a high-severity vulnerability in Active Directory Certificate Services, dubbed 'Certighost', which could allow an attacker to escalate privileges and compromise an Active Directory environment. The flaw was disclosed by Dark Reading on July 28, 2026.

{{< ad-banner >}}

The vulnerability affects the certificate enrollment process, enabling a threat actor with low-level access to elevate their privileges to domain administrator. This could lead to full compromise of the AD infrastructure, including the ability to forge certificates and impersonate any user or device.

Organizations using Microsoft Active Directory Certificate Services are urged to apply the latest security updates immediately. The vulnerability underscores the critical nature of certificate services in maintaining trust within AD environments.

{{< netrunner-insight >}}

This is a classic AD certificate services attack vector. Ensure your certificate templates are hardened and that enrollment permissions are tightly controlled. Patch immediately and monitor for unusual certificate requests or privilege escalations.

{{< /netrunner-insight >}}

---

**[Read full article on Dark Reading ›](https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates)**
