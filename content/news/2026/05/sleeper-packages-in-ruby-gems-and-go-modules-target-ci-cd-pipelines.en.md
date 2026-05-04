---
title: "Sleeper Packages in Ruby Gems and Go Modules Target CI/CD Pipelines"
date: "2026-05-04T09:17:53Z"
original_date: "2026-05-01T09:43:00"
lang: "en"
translationKey: "sleeper-packages-in-ruby-gems-and-go-modules-target-ci-cd-pipelines"
author: "NewsBot (Validated by Federico Sella)"
description: "Attackers use sleeper packages to deliver malicious payloads, stealing credentials, tampering with GitHub Actions, and establishing SSH persistence in software supply chain attacks."
original_url: "https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html"
source: "The Hacker News"
severity: "High"
target: "CI/CD pipelines and software supply chains"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Attackers use sleeper packages to deliver malicious payloads, stealing credentials, tampering with GitHub Actions, and establishing SSH persistence in software supply chain attacks.

{{< cyber-report severity="High" source="The Hacker News" target="CI/CD pipelines and software supply chains" >}}

A new software supply chain attack campaign has been observed using sleeper packages as a conduit to subsequently push malicious payloads that enabled credential theft, GitHub Actions tampering, and SSH persistence. The activity has been attributed to the GitHub account "BufferZoneCorp," which has published a set of repositories that are associated with malicious Ruby gems and Go modules.

{{< ad-banner >}}

The attack leverages initially benign-looking packages that later receive malicious updates, a technique known as "sleeper" or "trojanized" packages. Once installed in CI/CD environments, the payloads steal credentials, modify GitHub Actions workflows, and establish persistent SSH access, posing a significant threat to development pipelines.

Organizations using Ruby gems or Go modules from untrusted sources should audit their dependencies and monitor for suspicious repository activity. The campaign highlights the evolving sophistication of supply chain attacks targeting developer infrastructure.

{{< netrunner-insight >}}

This campaign underscores the need for strict dependency pinning and integrity verification in CI/CD pipelines. SOC analysts should monitor for anomalous GitHub Actions modifications and SSH key additions, while DevSecOps engineers should implement least-privilege access and consider using ephemeral build environments to limit blast radius.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html)**
