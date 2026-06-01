---
title: "OpenAI Codex Auth Tokens Stolen in npm Supply Chain Attack"
date: "2026-06-01T12:34:23Z"
original_date: "2026-06-01T09:31:15"
lang: "en"
translationKey: "openai-codex-auth-tokens-stolen-in-npm-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Malicious npm package codexui-android targets developers, stealing OpenAI Codex authentication tokens with over 29,000 weekly downloads."
original_url: "https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html"
source: "The Hacker News"
severity: "High"
target: "OpenAI Codex developers"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Malicious npm package codexui-android targets developers, stealing OpenAI Codex authentication tokens with over 29,000 weekly downloads.

{{< cyber-report severity="High" source="The Hacker News" target="OpenAI Codex developers" >}}

Cybersecurity researchers have uncovered a malicious supply chain campaign targeting developers using OpenAI Codex. The attack leverages a legitimate-looking npm package named codexui-android, which is advertised as a remote web UI for OpenAI Codex on both GitHub and npm. The package has attracted over 29,000 weekly downloads, indicating significant reach within the developer community.

{{< ad-banner >}}

The malicious package is designed to steal OpenAI Codex authentication tokens from unsuspecting developers. As of the report, the package remains available for download, posing an ongoing threat. Developers who have installed codexui-android are advised to rotate their tokens immediately and audit their systems for unauthorized access.

This incident highlights the persistent risk of supply chain attacks in the open-source ecosystem. The use of legitimate-sounding package names and high download counts can lull developers into a false sense of security. Organizations should implement strict package vetting processes and consider using tools that detect anomalous package behavior.

{{< netrunner-insight >}}

For SOC analysts and DevSecOps engineers, this attack underscores the need to monitor npm package downloads and behavior. Implement runtime detection for unexpected token exfiltration and enforce least-privilege access for API tokens. Regularly audit your software supply chain and consider using package integrity verification tools.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html)**
