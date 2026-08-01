---
title: "Chinese Hacker Uses DeepSeek via Telegram to Launch Autonomous Attacks"
date: "2026-08-01T09:07:32Z"
original_date: "2026-07-31T11:21:27"
lang: "en"
translationKey: "chinese-hacker-uses-deepseek-via-telegram-to-launch-autonomous-attacks"
slug: "chinese-hacker-uses-deepseek-via-telegram-to-launch-autonomous-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "Unit 42 reports a Chinese-speaking threat actor leveraging DeepSeek through Hermes Agent to autonomously attack internet-facing systems after a single Telegram command."
original_url: "https://thehackernews.com/2026/07/chinese-hacker-commands-deepseek-via.html"
source: "The Hacker News"
severity: "High"
target: "Internet-facing systems"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Unit 42 reports a Chinese-speaking threat actor leveraging DeepSeek through Hermes Agent to autonomously attack internet-facing systems after a single Telegram command.

{{< cyber-report severity="High" source="The Hacker News" target="Internet-facing systems" >}}

Palo Alto Networks' Unit 42 has disclosed a novel attack chain in which a Chinese-speaking threat actor, tracked under the aliases knaithe and KnYuan, used the DeepSeek AI model through the open-source Hermes Agent framework to conduct autonomous attacks. The operation began with a single Telegram instruction, after which the agent independently identified internet-facing systems and selected appropriate public exploits.

{{< ad-banner >}}

According to the researchers, no further operator input was recovered during the session, indicating a high degree of automation. This marks a significant evolution in AI-assisted cyberattacks, where the AI agent handles reconnaissance, exploit selection, and execution without continuous human direction.

The findings underscore the growing threat of AI-driven autonomous attack tools, which lower the barrier for less-skilled attackers and increase the speed and scale of operations. Organizations must adapt their defenses to counter such automated threats, which can operate at machine speed and adapt to their environment.

{{< netrunner-insight >}}

This incident highlights the urgent need for SOCs to monitor for AI-driven attack patterns, such as rapid, automated exploitation attempts that may lack the typical human error signatures. DevSecOps teams should prioritize hardening internet-facing assets and implementing automated detection and response mechanisms to counter autonomous threats. Additionally, consider restricting AI model access and monitoring for unusual API usage that could indicate AI-assisted attacks.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/chinese-hacker-commands-deepseek-via.html)**
