---
title: "TONTOU CPU attack bypasses Spectre v2 fixes, leaks Linux password hashes"
date: "2026-08-10T08:26:15Z"
original_date: "2026-08-06T18:03:45"
lang: "en"
translationKey: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
slug: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "Researchers develop TONTOU attack that bypasses recent Spectre v2 mitigations, successfully leaking secrets including password hashes from Linux systems."
original_url: "https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/"
source: "BleepingComputer"
severity: "High"
target: "Linux systems"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Researchers develop TONTOU attack that bypasses recent Spectre v2 mitigations, successfully leaking secrets including password hashes from Linux systems.

{{< cyber-report severity="High" source="BleepingComputer" target="Linux systems" >}}

Security researchers have unveiled a new speculative execution attack, dubbed TONTOU, that circumvents recent mitigations for the Spectre v2 vulnerability. The attack targets the CPU's branch prediction mechanisms, which were previously patched to prevent side-channel leaks. By exploiting a gap in these defenses, the researchers were able to extract sensitive data from the kernel memory of Linux machines.

{{< ad-banner >}}

The proof-of-concept exploit demonstrates the severity of the issue by successfully leaking password hashes from the target system. This indicates that the attack could be used to compromise user credentials and potentially escalate privileges. The findings highlight the ongoing challenge of fully mitigating speculative execution side-channel attacks, as new variations continue to emerge despite prior fixes.

While the researchers have not yet released full technical details, their work underscores the need for continued vigilance in CPU security. System administrators are advised to monitor for updates from CPU vendors and Linux distributions, and to consider additional hardening measures such as kernel address space layout randomization (KASLR) and microcode updates.

{{< netrunner-insight >}}

This attack is a stark reminder that speculative execution vulnerabilities are not fully resolved. SOC analysts should prioritize patching and monitor for any indicators of exploitation, while DevSecOps engineers should review their threat models for side-channel risks. Given the potential to leak password hashes, immediate attention to Linux kernel updates and CPU microcode is warranted.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/)**
