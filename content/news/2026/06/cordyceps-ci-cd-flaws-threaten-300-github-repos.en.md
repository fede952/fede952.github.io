---
title: "Cordyceps CI/CD Flaws Threaten 300+ GitHub Repos"
date: "2026-06-25T10:14:17Z"
original_date: "2026-06-24T12:48:11"
lang: "en"
translationKey: "cordyceps-ci-cd-flaws-threaten-300-github-repos"
author: "NewsBot (Validated by Federico Sella)"
description: "New CI/CD workflow weakness codenamed Cordyceps allows attackers to hijack workflows and compromise open-source supply chains at major organizations."
original_url: "https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html"
source: "The Hacker News"
severity: "Critical"
target: "CI/CD workflows on GitHub"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

New CI/CD workflow weakness codenamed Cordyceps allows attackers to hijack workflows and compromise open-source supply chains at major organizations.

{{< cyber-report severity="Critical" source="The Hacker News" target="CI/CD workflows on GitHub" >}}

Cybersecurity researchers at Novee Security have identified a critical exploitable pattern in CI/CD workflows, dubbed Cordyceps, that can allow attackers to hijack workflows and compromise open-source supply chains. The flaw affects over 300 GitHub repositories belonging to major organizations including Microsoft, Google, and Apache.

{{< ad-banner >}}

The Cordyceps pattern enables full attacker control of repositories, potentially leading to unauthorized code changes, backdoor insertion, and downstream supply-chain attacks. The vulnerability stems from insecure workflow configurations that fail to properly isolate or validate inputs.

Organizations using GitHub Actions or similar CI/CD platforms are urged to review their workflow definitions for the Cordyceps pattern and implement least-privilege permissions, input sanitization, and environment isolation to mitigate the risk.

{{< netrunner-insight >}}

This is a textbook supply-chain attack vector. SOC analysts should monitor for anomalous workflow executions and unexpected repository changes. DevSecOps teams must audit CI/CD pipeline configurations immediately, focusing on untrusted input handling and permission scoping.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)**
