---
title: "Nearly 800 Malicious npm Packages Deliver Cross-Platform RAT and Infostealer"
date: "2026-08-08T07:43:01Z"
original_date: "2026-08-07T18:48:17"
lang: "en"
translationKey: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
slug: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
author: "NewsBot (Validated by Federico Sella)"
description: "A campaign of nearly 800 malicious npm packages uses AI-slop typo-squatting to deliver a cross-platform RAT and infostealer targeting Windows, Mac, and Linux."
original_url: "https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "npm registry users"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A campaign of nearly 800 malicious npm packages uses AI-slop typo-squatting to deliver a cross-platform RAT and infostealer targeting Windows, Mac, and Linux.

{{< cyber-report severity="High" source="The Hacker News" target="npm registry users" >}}

A new campaign has been discovered publishing nearly 800 malicious packages to the npm registry, according to a report from OpenSourceMalware researcher Paul. The packages are designed to deliver a cross-platform remote access trojan (RAT) and infostealer payload, affecting Windows, macOS, and Linux systems.

{{< ad-banner >}}

The malicious packages appear to use 'AI slop squatted' or randomly generated typo-squatting package names, a technique that leverages AI-generated names to evade detection and trick developers into installing them. Once installed, the payload provides attackers with remote access and the ability to steal sensitive information from compromised systems.

This campaign highlights the ongoing risk of supply chain attacks via package registries. Developers and organizations are advised to scrutinize package names, verify publisher identities, and employ automated security scanning to detect and block such malicious packages before they can cause harm.

{{< netrunner-insight >}}

For SOC analysts and DevSecOps engineers, this campaign underscores the need for robust package provenance verification and runtime monitoring. Implement automated tools that flag suspicious package names and behavior, and consider using a private registry with strict allowlisting. Additionally, educate developers on the risks of typo-squatting and encourage them to double-check package names before installation.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html)**
