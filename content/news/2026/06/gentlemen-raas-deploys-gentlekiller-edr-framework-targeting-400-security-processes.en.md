---
title: "Gentlemen RaaS Deploys GentleKiller EDR Framework Targeting 400 Security Processes"
date: "2026-06-21T10:29:36Z"
original_date: "2026-06-19T18:33:07"
lang: "en"
translationKey: "gentlemen-raas-deploys-gentlekiller-edr-framework-targeting-400-security-processes"
author: "NewsBot (Validated by Federico Sella)"
description: "The Gentlemen ransomware-as-a-service operation uses a mature EDR-killing framework called GentleKiller to disable defenses before deploying ransomware, targeting over 400 security processes."
original_url: "https://thehackernews.com/2026/06/the-gentlemen-raas-uses-gentlekiller.html"
source: "The Hacker News"
severity: "High"
target: "Endpoint detection and response systems"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

The Gentlemen ransomware-as-a-service operation uses a mature EDR-killing framework called GentleKiller to disable defenses before deploying ransomware, targeting over 400 security processes.

{{< cyber-report severity="High" source="The Hacker News" target="Endpoint detection and response systems" >}}

The Gentlemen ransomware-as-a-service (RaaS) operation is actively developing and maintaining a suite of endpoint detection and response (EDR) killers that it provides to affiliates to impair system defenses before deploying the encryptor. This mature portfolio of EDR-terminating tools is centered around a framework known as GentleKiller.

{{< ad-banner >}}

The framework targets over 400 security processes, effectively neutralizing a wide range of EDR solutions. By disabling these defenses, affiliates can execute the ransomware payload with reduced risk of detection or interruption.

The use of such a dedicated EDR-killing framework indicates a high level of sophistication and resource investment by the Gentlemen RaaS operation. Organizations should ensure their EDR solutions are updated and consider additional layers of defense to mitigate this threat.

{{< netrunner-insight >}}

SOC analysts should monitor for unusual termination of security processes and implement process-level monitoring to detect GentleKiller activity. DevSecOps teams should harden EDR solutions against tampering and consider deploying multiple, diverse security tools to increase resilience against such targeted attacks.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/06/the-gentlemen-raas-uses-gentlekiller.html)**
