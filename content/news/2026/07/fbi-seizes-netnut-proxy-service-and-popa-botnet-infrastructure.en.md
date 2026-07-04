---
title: "FBI Seizes NetNut Proxy Service and Popa Botnet Infrastructure"
date: "2026-07-04T09:20:04Z"
original_date: "2026-07-02T19:27:33"
lang: "en"
translationKey: "fbi-seizes-netnut-proxy-service-and-popa-botnet-infrastructure"
author: "NewsBot (Validated by Federico Sella)"
description: "The FBI has seized domains linked to NetNut, a residential proxy service tied to the Popa botnet of 2 million compromised devices, following investigative reporting."
original_url: "https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/"
source: "Krebs on Security"
severity: "High"
target: "Residential proxy service NetNut and Popa botnet"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

The FBI has seized domains linked to NetNut, a residential proxy service tied to the Popa botnet of 2 million compromised devices, following investigative reporting.

{{< cyber-report severity="High" source="Krebs on Security" target="Residential proxy service NetNut and Popa botnet" >}}

The FBI, in coordination with industry partners, has seized hundreds of domains associated with NetNut, a residential proxy service operated by the publicly-traded Israeli company Alarum Technologies (NASDAQ: ALAR). The action follows a KrebsOnSecurity report linking NetNut to the Popa botnet, a network of at least two million devices compromised without user consent.

{{< ad-banner >}}

The Popa botnet leverages infected devices to route traffic through NetNut's proxy infrastructure, enabling malicious activities such as credential stuffing, ad fraud, and account takeover. The seizure disrupts both the proxy service and the botnet's command-and-control capabilities.

This operation highlights the growing trend of law enforcement targeting proxy services that facilitate cybercrime. Organizations should review their network traffic for connections to seized domains and monitor for residual botnet activity.

{{< netrunner-insight >}}

For SOC analysts, this takedown underscores the importance of monitoring residential proxy IP ranges in threat intelligence feeds. DevSecOps teams should audit any integrations with third-party proxy services and ensure robust botnet detection mechanisms are in place, as remnants of Popa may persist in alternate infrastructure.

{{< /netrunner-insight >}}

---

**[Read full article on Krebs on Security ›](https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/)**
