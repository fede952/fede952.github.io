---
title: "China-Linked Hackers Backdoored Linux Login Software for Nearly a Decade"
date: "2026-06-15T13:04:59Z"
original_date: "2026-06-12T18:17:55"
lang: "en"
translationKey: "china-linked-hackers-backdoored-linux-login-software-for-nearly-a-decade"
author: "NewsBot (Validated by Federico Sella)"
description: "A China-nexus group known as Velvet Ant compromised PAM and OpenSSH components, hiding in Linux login systems for almost ten years without detection."
original_url: "https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html"
source: "The Hacker News"
severity: "High"
target: "Linux login systems (PAM, OpenSSH)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A China-nexus group known as Velvet Ant compromised PAM and OpenSSH components, hiding in Linux login systems for almost ten years without detection.

{{< cyber-report severity="High" source="The Hacker News" target="Linux login systems (PAM, OpenSSH)" >}}

A China-linked threat actor tracked as Velvet Ant has been found to have backdoored core Linux login components, including PAM (Pluggable Authentication Modules) and OpenSSH, allowing them to maintain persistent access for nearly a decade. The group targeted a network where they embedded their backdoor deep within the authentication stack, making it resistant to standard cleanup procedures.

{{< ad-banner >}}

According to security firm Sygnia, the attackers exploited the trust placed in login software to evade detection. By modifying the very mechanisms that control user access, they ensured their foothold survived system updates and routine security scans. The campaign highlights the increasing sophistication of state-sponsored groups in targeting foundational infrastructure.

The compromise underscores the need for organizations to monitor integrity of critical system components beyond typical endpoint detection. Defenders should consider file integrity monitoring for PAM modules and SSH binaries, as well as behavioral analysis of authentication logs to spot anomalies indicative of backdoored login processes.

{{< netrunner-insight >}}

For SOC analysts and DevSecOps teams, this is a stark reminder that attackers are targeting the authentication layer itself. Implement runtime integrity checks on PAM and OpenSSH binaries, and consider using kernel-level monitoring to detect tampering. Also, review SSH key-based authentication and PAM configuration changes as part of your incident response playbooks.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html)**
