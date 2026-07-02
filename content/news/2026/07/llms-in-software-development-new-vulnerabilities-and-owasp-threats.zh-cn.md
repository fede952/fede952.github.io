---
title: "软件开发中的LLM：新漏洞与OWASP威胁"
date: "2026-07-02T09:55:59Z"
original_date: "2026-07-01T14:47:31"
lang: "zh-cn"
translationKey: "llms-in-software-development-new-vulnerabilities-and-owasp-threats"
author: "NewsBot (Validated by Federico Sella)"
description: "AI驱动的编码助手加速开发，但引入了不安全代码、幻觉库、提示注入和数据泄露等风险。了解OWASP威胁及安全采用策略。"
original_url: "https://www.cybersecurity360.it/soluzioni-aziendali/intelligenza-artificiale-e-vulnerabilita-il-ruolo-dei-modelli-llm-nel-codice-applicativo/"
source: "Cybersecurity360"
severity: "Medium"
target: "使用LLM的软件开发流水线"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

AI驱动的编码助手加速开发，但引入了不安全代码、幻觉库、提示注入和数据泄露等风险。了解OWASP威胁及安全采用策略。

{{< cyber-report severity="Medium" source="Cybersecurity360" target="使用LLM的软件开发流水线" >}}

大型语言模型（LLM）越来越多地被用于生成应用程序代码，提高了开发人员生产力，但也引入了新的安全风险。自动生成的代码可能包含注入缺陷、不安全的加密实践或逻辑错误等漏洞，这些漏洞在没有专门审查的情况下难以发现。

{{< ad-banner >}}

一个关键问题是幻觉，即LLM建议不存在的库或API，如果开发人员无意中导入恶意软件包，可能导致供应链攻击。此外，提示注入攻击可以操纵LLM行为，而数据泄露可能暴露嵌入在训练数据或用户交互中的敏感信息。

OWASP LLM应用十大威胁突出了这些风险，包括提示注入、不安全的输出处理和训练数据投毒。为降低风险，组织应实施严格的代码审查，使用静态分析工具，限制LLM对敏感数据的访问，并采用针对AI生成代码量身定制的安全编码指南。

{{< netrunner-insight >}}

对于SOC分析师和DevSecOps工程师，将LLM生成的代码视为不受信任的输入。将自动安全扫描集成到CI/CD流水线中，并对AI建议的任何外部依赖项实施严格验证。考虑在隔离环境中部署LLM，并赋予最小权限，以限制提示注入或数据泄露的爆炸半径。

{{< /netrunner-insight >}}

---

**[在 Cybersecurity360 上阅读全文 ›](https://www.cybersecurity360.it/soluzioni-aziendali/intelligenza-artificiale-e-vulnerabilita-il-ruolo-dei-modelli-llm-nel-codice-applicativo/)**
