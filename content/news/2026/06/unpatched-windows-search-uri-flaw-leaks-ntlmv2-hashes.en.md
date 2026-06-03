---
title: "Unpatched Windows Search URI Flaw Leaks NTLMv2 Hashes"
date: "2026-06-03T11:53:18Z"
original_date: "2026-06-03T10:18:52"
lang: "en"
translationKey: "unpatched-windows-search-uri-flaw-leaks-ntlmv2-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "Researchers disclose an unpatched vulnerability in the Windows search: URI handler that can expose NTLMv2 hashes, similar to the CVE-2026-33829 Snipping Tool flaw."
original_url: "https://thehackernews.com/2026/06/unpatched-windows-search-uri.html"
source: "The Hacker News"
severity: "High"
target: "Windows search: URI handler"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Researchers disclose an unpatched vulnerability in the Windows search: URI handler that can expose NTLMv2 hashes, similar to the CVE-2026-33829 Snipping Tool flaw.

{{< cyber-report severity="High" source="The Hacker News" target="Windows search: URI handler" >}}

Cybersecurity researchers at Huntress have disclosed details of an unpatched vulnerability in the Windows search: URI handler that could allow attackers to steal NTLMv2 hashes. The issue is reminiscent of CVE-2026-33829, a spoofing vulnerability in the Windows Snipping Tool's ms-screensketch: URI handler that also exposed NTLM hashes.

{{< ad-banner >}}

The newly identified flaw resides in the search: URI scheme, which is used to launch Windows Search queries. By crafting a malicious link or file that triggers the search: URI handler, an attacker can force the target system to authenticate to a remote server, thereby leaking the user's NTLMv2 hash. This hash can then be cracked offline or used in relay attacks.

As of the publication date, no official patch has been released by Microsoft. Organizations are advised to monitor for updates and consider blocking the search: URI handler via group policy or endpoint security tools until a fix is available.

{{< netrunner-insight >}}

This is a classic NTLM relay vector that SOC analysts should watch for in authentication logs. DevSecOps engineers should immediately review any use of URI handlers in their environments and consider applying mitigations like disabling NTLMv2 or enforcing SMB signing. Until Microsoft patches this, assume the search: URI is a potential entry point for credential theft.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/06/unpatched-windows-search-uri.html)**
