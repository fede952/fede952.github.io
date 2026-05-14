---
title: "Falha crítica no Exim permite execução remota de código"
date: "2026-05-14T09:33:22Z"
original_date: "2026-05-13T20:23:50"
lang: "pt"
translationKey: "critical-exim-mailer-flaw-allows-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "Uma vulnerabilidade crítica nas configurações do agente de transferência de correio Exim pode permitir que atacantes não autenticados executem código arbitrário remotamente. Corrija imediatamente."
original_url: "https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/"
source: "BleepingComputer"
severity: "Critical"
target: "Agente de transferência de correio Exim"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Uma vulnerabilidade crítica nas configurações do agente de transferência de correio Exim pode permitir que atacantes não autenticados executem código arbitrário remotamente. Corrija imediatamente.

{{< cyber-report severity="Critical" source="BleepingComputer" target="Agente de transferência de correio Exim" >}}

Uma vulnerabilidade crítica foi descoberta no agente de transferência de correio de código aberto Exim que afeta certas configurações. A falha pode permitir que um atacante remoto não autenticado execute código arbitrário em sistemas vulneráveis.

{{< ad-banner >}}

O Exim é amplamente utilizado como servidor de correio em sistemas Unix-like, tornando esta vulnerabilidade particularmente preocupante para organizações que dependem dele para entrega de e-mail. Os detalhes técnicos exatos da exploração não foram totalmente divulgados, mas a classificação de gravidade indica que a correção imediata é recomendada.

Os administradores devem revisar suas configurações do Exim e aplicar todas as atualizações disponíveis do projeto Exim. Até que as correções sejam implantadas, considere implementar controles de acesso no nível da rede para limitar a exposição ao serviço vulnerável.

{{< netrunner-insight >}}

Este é um vetor crítico de execução remota de código em um MTA amplamente implantado. Os analistas do SOC devem priorizar a varredura de instâncias do Exim e verificar o endurecimento da configuração. As equipes DevSecOps devem acelerar a correção e considerar regras de WAF para bloquear tentativas de exploração até que as atualizações sejam aplicadas.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/)**
