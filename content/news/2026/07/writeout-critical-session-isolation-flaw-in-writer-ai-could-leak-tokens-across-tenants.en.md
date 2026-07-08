---
title: "WriteOut: Critical Session Isolation Flaw in Writer AI Could Leak Tokens Across Tenants"
date: "2026-07-08T09:23:55Z"
original_date: "2026-07-07T13:27:09"
lang: "en"
translationKey: "writeout-critical-session-isolation-flaw-in-writer-ai-could-leak-tokens-across-tenants"
slug: "writeout-critical-session-isolation-flaw-in-writer-ai-could-leak-tokens-across-tenants"
author: "NewsBot (Validated by Federico Sella)"
description: "A one-click vulnerability in Writer AI, codenamed WriteOut, could allow cross-tenant session token leakage. The flaw is now patched."
original_url: "https://thehackernews.com/2026/07/writer-ai-flaw-could-let-agent-previews.html"
source: "The Hacker News"
severity: "Critical"
target: "Writer AI enterprise platform"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A one-click vulnerability in Writer AI, codenamed WriteOut, could allow cross-tenant session token leakage. The flaw is now patched.

{{< cyber-report severity="Critical" source="The Hacker News" target="Writer AI enterprise platform" >}}

Cybersecurity researchers at Sand Security have disclosed a critical session isolation vulnerability in Writer, an enterprise generative AI platform. The flaw, dubbed WriteOut, could enable an attacker to leak session tokens across tenants, leading to cross-tenant compromise with a single click.

{{< ad-banner >}}

The vulnerability stems from improper session isolation in the agent preview feature, allowing an outsider to escalate from no access to full takeover of any Writer AI tenant. Writer has since patched the issue, but the discovery highlights the risks of multi-tenant AI platforms.

Organizations using Writer AI should verify that the latest patches are applied and review session management configurations. The WriteOut vulnerability serves as a reminder to prioritize tenant isolation in cloud-based AI services.

{{< netrunner-insight >}}

For SOC analysts: monitor for anomalous session token usage and cross-tenant access patterns in Writer AI logs. DevSecOps teams should enforce strict session isolation and consider implementing additional tenant boundary checks in multi-tenant AI deployments.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/writer-ai-flaw-could-let-agent-previews.html)**
