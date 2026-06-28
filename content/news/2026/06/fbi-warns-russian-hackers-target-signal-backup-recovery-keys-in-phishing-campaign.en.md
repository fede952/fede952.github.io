---
title: "FBI Warns Russian Hackers Target Signal Backup Recovery Keys in Phishing Campaign"
date: "2026-06-28T09:56:23Z"
original_date: "2026-06-26T22:06:17"
lang: "en"
translationKey: "fbi-warns-russian-hackers-target-signal-backup-recovery-keys-in-phishing-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "The FBI and CISA warn that Russian intelligence-linked phishing attacks now steal Signal Backup Recovery Keys, enabling access to victims' historical messages."
original_url: "https://www.bleepingcomputer.com/news/security/fbi-russian-hackers-now-target-signal-backup-recovery-keys/"
source: "BleepingComputer"
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

The FBI and CISA warn that Russian intelligence-linked phishing attacks now steal Signal Backup Recovery Keys, enabling access to victims' historical messages.

{{< cyber-report severity="High" source="BleepingComputer" target="Signal users" >}}

The FBI and CISA have issued a joint warning that a phishing campaign attributed to Russian intelligence services has evolved to target Signal Backup Recovery Keys. These keys, typically used to restore message history on a new device, can be stolen to give attackers access to a victim's past conversations and contacts.

{{< ad-banner >}}

The campaign initially focused on stealing Signal login credentials but has now expanded to exfiltrate recovery keys. Attackers use social engineering tactics, such as fake Signal group invitations or security alerts, to trick users into revealing their recovery keys.

Organizations and individuals using Signal for sensitive communications are urged to enable additional security measures, such as registration lock and screen lock, and to verify the authenticity of any requests for recovery keys or login credentials.

{{< netrunner-insight >}}

SOC analysts should monitor for phishing lures impersonating Signal group invites or security alerts, as these are now being used to harvest recovery keys. DevSecOps teams should enforce multi-factor authentication and educate users that legitimate services never ask for recovery keys or passwords via unsolicited messages.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/fbi-russian-hackers-now-target-signal-backup-recovery-keys/)**
