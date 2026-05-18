---
title: "MiniPlasma Windows 0-Day Enables SYSTEM Privilege Escalation on Fully Patched Systems"
date: "2026-05-18T11:01:35Z"
original_date: "2026-05-18T08:57:34"
lang: "en"
translationKey: "miniplasma-windows-0-day-enables-system-privilege-escalation-on-fully-patched-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "Security researcher Chaotic Eclipse releases PoC for MiniPlasma, a zero-day in Windows Cloud Files Mini Filter Driver (cldflt.sys) granting SYSTEM privileges on fully patched systems."
original_url: "https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html"
source: "The Hacker News"
severity: "High"
target: "Windows Cloud Files Mini Filter Driver (cldflt.sys)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Security researcher Chaotic Eclipse releases PoC for MiniPlasma, a zero-day in Windows Cloud Files Mini Filter Driver (cldflt.sys) granting SYSTEM privileges on fully patched systems.

{{< cyber-report severity="High" source="The Hacker News" target="Windows Cloud Files Mini Filter Driver (cldflt.sys)" >}}

Chaotic Eclipse, the security researcher behind the recently disclosed Windows flaws YellowKey and GreenPlasma, has released a proof-of-concept (PoC) for a Windows privilege escalation zero-day flaw that grants attackers SYSTEM privileges on fully patched Windows systems. Codenamed MiniPlasma, the vulnerability impacts "cldflt.sys," which refers to the Windows Cloud Files Mini Filter Driver.

{{< ad-banner >}}

The flaw allows an attacker with limited user access to escalate privileges to SYSTEM, potentially enabling full system compromise. As a zero-day, no official patch is currently available, leaving fully patched systems vulnerable to exploitation if the PoC is weaponized.

Organizations should monitor for unusual behavior from the cldflt.sys driver and consider additional hardening measures, such as restricting access to the Cloud Files feature or applying temporary mitigations until a patch is released.

{{< netrunner-insight >}}

SOC analysts should prioritize monitoring for exploitation attempts targeting cldflt.sys, as the PoC lowers the barrier for attackers. DevSecOps teams should review their Windows image hardening and consider disabling the Cloud Files Mini Filter Driver if not required, while awaiting an official fix from Microsoft.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)**
