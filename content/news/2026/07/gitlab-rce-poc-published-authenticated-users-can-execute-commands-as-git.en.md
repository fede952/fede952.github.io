---
title: "GitLab RCE PoC Published: Authenticated Users Can Execute Commands as Git"
date: "2026-07-27T10:37:15Z"
original_date: "2026-07-25T10:14:26"
lang: "en"
translationKey: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
slug: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
author: "NewsBot (Validated by Federico Sella)"
description: "A proof-of-concept exploit for a GitLab remote code execution flaw was released, targeting unpatched self-managed 18.11.3 servers. Authenticated users can run commands as the git user."
original_url: "https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html"
source: "The Hacker News"
severity: "High"
target: "GitLab self-managed 18.11.3"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A proof-of-concept exploit for a GitLab remote code execution flaw was released, targeting unpatched self-managed 18.11.3 servers. Authenticated users can run commands as the git user.

{{< cyber-report severity="High" source="The Hacker News" target="GitLab self-managed 18.11.3" >}}

On July 24, 2026, security researchers at depthfirst published a working proof-of-concept exploit for a GitLab remote code execution vulnerability. The flaw, which GitLab patched on June 10, 2026, allows any authenticated user with push access to a project to execute arbitrary commands as the git user on self-managed GitLab 18.11.3 servers that have not applied the update.

{{< ad-banner >}}

The exploit leverages a crafted Jupyter notebook committed to a project. When the attacker opens the commit diff, the malicious notebook triggers a heap leak, enabling command execution. This technique bypasses typical authentication controls and requires no special privileges beyond standard project access.

Organizations running self-managed GitLab instances should immediately verify they have applied the June 10 patch. The public availability of exploit code increases the risk of active exploitation, particularly for instances exposed to the internet. Blue teams should monitor for unusual Jupyter notebook commits and unexpected git user activity.

{{< netrunner-insight >}}

This exploit underscores the danger of delayed patching in self-managed CI/CD platforms. SOC analysts should prioritize detection of anomalous git user processes and unexpected Jupyter notebook uploads. DevSecOps teams must enforce a strict patch window for GitLab and consider network segmentation to limit exposure of self-managed instances.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)**
