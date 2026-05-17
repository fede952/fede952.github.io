---
title: "CISA Warns of Siemens Opcenter RDnL Flaw via ActiveMQ Artemis Missing Auth"
date: "2026-05-17T08:59:55Z"
original_date: "2026-05-14T12:00:00"
lang: "en"
translationKey: "cisa-warns-of-siemens-opcenter-rdnl-flaw-via-activemq-artemis-missing-auth"
author: "NewsBot (Validated by Federico Sella)"
description: "Siemens Opcenter RDnL affected by CVE-2026-27446, a missing authentication vulnerability in ActiveMQ Artemis that allows unauthenticated adjacent attackers to inject or exfiltrate messages."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09"
source: "CISA"
severity: "High"
target: "Siemens Opcenter RDnL"
cve: "CVE-2026-27446"
cvss: 7.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Siemens Opcenter RDnL affected by CVE-2026-27446, a missing authentication vulnerability in ActiveMQ Artemis that allows unauthenticated adjacent attackers to inject or exfiltrate messages.

{{< cyber-report severity="High" source="CISA" target="Siemens Opcenter RDnL" cve="CVE-2026-27446" cvss="7.1" >}}

CISA has published an advisory (ICSA-26-134-09) detailing a missing authentication for critical function vulnerability in Apache ActiveMQ Artemis, affecting Siemens Opcenter RDnL. The flaw, tracked as CVE-2026-27446 with a CVSS v3 score of 7.1, allows an unauthenticated attacker within the adjacent network to force a target broker to establish an outbound Core federation connection to a rogue broker. This can lead to message injection into any queue or message exfiltration from any queue via the rogue broker.

{{< ad-banner >}}

The vulnerability impacts all versions of Siemens Opcenter RDnL. While the integrity impact is considered low due to missing auto-refresh functionality and the absence of confidential information in the messages, the availability impact and potential for message manipulation remain significant. ActiveMQ Artemis has released a fix, and Siemens recommends updating to the latest version immediately.

Given the critical manufacturing sector deployment worldwide, organizations using Opcenter RDnL should prioritize patching. The adjacent network attack vector reduces the immediate exposure but still poses a risk in segmented environments. Blue teams should monitor for unusual Core federation connections and rogue broker activity.

{{< netrunner-insight >}}

For SOC analysts, monitor for unexpected outbound Core federation connections from ActiveMQ Artemis brokers, as this is the primary indicator of exploitation. DevSecOps teams should immediately update to the latest ActiveMQ Artemis version and restrict Core protocol access to trusted networks only. This flaw underscores the risk of missing authentication in middleware components, even when the immediate impact seems low.

{{< /netrunner-insight >}}

---

**[Read full article on CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09)**
