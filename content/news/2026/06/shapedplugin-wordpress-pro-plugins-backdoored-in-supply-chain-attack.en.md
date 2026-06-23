---
title: "ShapedPlugin WordPress Pro Plugins Backdoored in Supply Chain Attack"
date: "2026-06-23T10:30:52Z"
original_date: "2026-06-22T18:00:48"
lang: "en"
translationKey: "shapedplugin-wordpress-pro-plugins-backdoored-in-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Multiple ShapedPlugin WordPress Pro plugins were compromised via a supply chain attack, with backdoor code injected into official releases."
original_url: "https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html"
source: "The Hacker News"
severity: "High"
target: "WordPress Pro plugins from ShapedPlugin"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Multiple ShapedPlugin WordPress Pro plugins were compromised via a supply chain attack, with backdoor code injected into official releases.

{{< cyber-report severity="High" source="The Hacker News" target="WordPress Pro plugins from ShapedPlugin" >}}

Multiple WordPress plugins from ShapedPlugin were compromised in a supply chain attack after unknown threat actors managed to tamper with the official release channels and push backdoor code. According to Wordfence, attackers compromised the vendor's build and distribution pipeline, injecting backdoor code into Pro plugin releases distributed through official licensed update channels.

{{< ad-banner >}}

The attack highlights the risks associated with third-party plugin ecosystems, where a single compromised vendor can impact numerous websites. Users of ShapedPlugin Pro plugins are advised to verify the integrity of their installations and update to the latest patched versions if available.

Wordfence has released a detailed analysis of the backdoor code, which can be used to detect compromised installations. Organizations should review their WordPress environments for any signs of unauthorized access or malicious activity.

{{< netrunner-insight >}}

This supply chain attack underscores the critical need for software supply chain security controls. SOC analysts should monitor for anomalous plugin update behaviors and consider implementing integrity checks for all third-party code. DevSecOps teams must enforce strict pipeline security and code signing to prevent similar compromises.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html)**
