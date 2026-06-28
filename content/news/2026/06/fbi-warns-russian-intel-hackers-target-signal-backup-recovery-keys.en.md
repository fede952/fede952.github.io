---
title: "FBI Warns Russian Intel Hackers Target Signal Backup Recovery Keys"
date: "2026-06-28T09:57:31Z"
original_date: "2026-06-26T19:38:29"
lang: "en"
translationKey: "fbi-warns-russian-intel-hackers-target-signal-backup-recovery-keys"
author: "NewsBot (Validated by Federico Sella)"
description: "FBI and CISA update warning: Russian intelligence phishing now steals Signal Backup Recovery Keys to read private messages and take over accounts."
original_url: "https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html"
source: "The Hacker News"
severity: "High"
target: "Signal users"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

FBI and CISA update warning: Russian intelligence phishing now steals Signal Backup Recovery Keys to read private messages and take over accounts.

{{< cyber-report severity="High" source="The Hacker News" target="Signal users" >}}

The FBI and CISA have updated their March warning about Russian intelligence phishing campaigns targeting Signal accounts. The attackers have added a new step: they now coax targets into handing over their Signal Backup Recovery Key. Once obtained, the key allows the attacker to restore the account's backup, read private and group message history, and take over the account entirely.

{{< ad-banner >}}

The key remains valid even after the initial compromise, enabling persistent access. This technique bypasses traditional two-factor authentication because the recovery key is designed for legitimate account restoration. The advisory emphasizes that users should never share their recovery key and should enable registration lock and other security features.

Organizations should educate users about this specific phishing vector and consider implementing additional verification steps for sensitive communications. The threat is attributed to Russian intelligence actors, highlighting the geopolitical context of the campaign.

{{< netrunner-insight >}}

This is a textbook example of social engineering targeting a security feature. SOC analysts should monitor for unusual account recovery requests and educate users that Signal's Backup Recovery Key must never be shared. DevSecOps teams should consider integrating phishing-resistant authentication for critical communications.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html)**
