---
title: "Três Falhas no OpenClaw Permitem Cadeia de Ataque do WhatsApp ao Host"
date: "2026-07-11T08:46:01Z"
original_date: "2026-07-10T14:19:50"
lang: "pt"
translationKey: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
slug: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
author: "NewsBot (Validated by Federico Sella)"
description: "Pesquisador detalha três vulnerabilidades de alta gravidade no OpenClaw que podem permitir roubo de credenciais, escalonamento de privilégios e execução de código no host."
original_url: "https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html"
source: "The Hacker News"
severity: "High"
target: "Assistente de IA OpenClaw"
cve: null
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Pesquisador detalha três vulnerabilidades de alta gravidade no OpenClaw que podem permitir roubo de credenciais, escalonamento de privilégios e execução de código no host.

{{< cyber-report severity="High" source="The Hacker News" target="Assistente de IA OpenClaw" cvss="8.8" >}}

Detalhes surgiram sobre três falhas de segurança já corrigidas no assistente pessoal de IA OpenClaw que, se exploradas com sucesso, podem permitir roubo de credenciais, escalonamento de privilégios e execução arbitrária de código no host. As vulnerabilidades foram divulgadas por um pesquisador que descreveu uma cadeia de ataque iniciada a partir de mensagens do WhatsApp.

{{< ad-banner >}}

Uma das falhas, rastreada como GHSA-hjr6-g723-hmfm com pontuação CVSS de 8,8, é descrita como de alta gravidade. A natureza exata das outras duas vulnerabilidades não foi totalmente detalhada, mas elas representam coletivamente um risco significativo para usuários que integram o OpenClaw com plataformas de mensagens como o WhatsApp.

A cadeia de ataque aproveita a capacidade do assistente de IA de processar mensagens, potencialmente permitindo que um invasor escale privilégios e execute código arbitrário no sistema host. Os usuários são aconselhados a aplicar as correções mais recentes para mitigar esses riscos.

{{< netrunner-insight >}}

Esta cadeia de ataque destaca os riscos de integrar assistentes de IA com plataformas de mensagens. Analistas de SOC devem monitorar execuções de processos incomuns originadas de componentes do assistente de IA, enquanto equipes de DevSecOps devem garantir que tais integrações sejam isoladas em sandbox e corrigidas prontamente.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html)**
