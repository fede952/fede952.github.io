---
title: "Malicious Edge extension 'Edgecution' uses Native Messaging to deploy backdoor"
date: "2026-06-25T10:16:09Z"
original_date: "2026-06-24T20:58:22"
lang: "en"
translationKey: "malicious-edge-extension-edgecution-uses-native-messaging-to-deploy-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "A malicious Microsoft Edge extension named 'Edgecution' escapes the browser sandbox via Native Messaging to deploy a Python-based backdoor in ransomware attacks."
original_url: "https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/"
source: "BleepingComputer"
severity: "High"
target: "Microsoft Edge users"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A malicious Microsoft Edge extension named 'Edgecution' escapes the browser sandbox via Native Messaging to deploy a Python-based backdoor in ransomware attacks.

{{< cyber-report severity="High" source="BleepingComputer" target="Microsoft Edge users" >}}

A malicious Microsoft Edge extension dubbed 'Edgecution' has been observed in a ransomware attack, leveraging the browser's Native Messaging API to escape the sandbox and execute arbitrary code on the host system. The extension acts as a bridge to deploy a Python-based backdoor, enabling persistent access and further malicious activities.

{{< ad-banner >}}

The attack chain begins with the installation of the rogue extension, which then abuses Native Messaging to communicate with a native application outside the browser sandbox. This technique bypasses typical browser security boundaries, allowing the attacker to execute commands and drop additional payloads, including ransomware.

Security researchers highlight that this method is particularly insidious because it exploits a legitimate browser feature, making detection challenging for traditional endpoint security solutions. Organizations are advised to monitor for unauthorized browser extensions and restrict Native Messaging permissions where possible.

{{< netrunner-insight >}}

This attack underscores the importance of monitoring browser extension installations and Native Messaging activity. SOC analysts should look for anomalous extension behaviors and unexpected native host communications, while DevSecOps teams should enforce strict extension allowlists and disable unnecessary Native Messaging hosts.

{{< /netrunner-insight >}}

---

**[Read full article on BleepingComputer ›](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)**
