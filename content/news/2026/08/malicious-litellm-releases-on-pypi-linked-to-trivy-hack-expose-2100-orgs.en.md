---
title: "Malicious LiteLLM Releases on PyPI Linked to Trivy Hack Expose 2,100+ Orgs"
date: "2026-08-17T07:48:06Z"
original_date: "2026-08-12T08:04:52"
lang: "en"
translationKey: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
slug: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
author: "NewsBot (Validated by Federico Sella)"
description: "Two malicious LiteLLM packages on PyPI stole cloud keys, SSH keys, and more. CloudSEK data suggests over 2,100 organizations may be exposed."
original_url: "https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html"
source: "The Hacker News"
severity: "High"
target: "LiteLLM users on PyPI"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Two malicious LiteLLM packages on PyPI stole cloud keys, SSH keys, and more. CloudSEK data suggests over 2,100 organizations may be exposed.

{{< cyber-report severity="High" source="The Hacker News" target="LiteLLM users on PyPI" >}}

Two malicious LiteLLM releases were published on PyPI and remained available for approximately 40 minutes in March. These packages contained credential-stealing code designed to harvest a wide range of secrets, including cloud access keys, SSH private keys, Kubernetes tokens, and database passwords from any system that installed them.

{{< ad-banner >}}

Threat intelligence firm CloudSEK obtained a dataset built from roughly 434,000 files that the attackers captured. Analysis of this dataset suggests that the exposure may affect more than 2,100 organizations, highlighting the potential scale of the compromise.

The incident is tied to the earlier Trivy hack, indicating a coordinated supply chain attack. Organizations that installed LiteLLM from PyPI during the affected window should immediately rotate all exposed credentials and investigate for signs of unauthorized access.

{{< netrunner-insight >}}

This incident underscores the critical need for software supply chain vigilance. SOC analysts should monitor for any installations of the malicious LiteLLM versions and prioritize credential rotation for any potentially exposed secrets. DevSecOps teams should enforce strict package integrity checks and consider using private mirrors or lock files with hashes to mitigate such risks.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html)**
