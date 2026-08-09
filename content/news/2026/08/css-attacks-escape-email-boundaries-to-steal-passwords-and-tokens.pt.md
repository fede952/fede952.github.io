---
title: "Ataques CSS Rompem Limites de E-mail para Roubar Senhas e Tokens"
date: "2026-08-09T07:52:16Z"
original_date: "2026-08-08T08:03:57"
lang: "pt"
translationKey: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
slug: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Nova pesquisa revela ataques baseados em CSS que escapam do conteúdo de e-mail para sequestrar interfaces de webmail, roubando credenciais e tokens em grandes provedores."
original_url: "https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html"
source: "The Hacker News"
severity: "High"
target: "Interfaces de webmail (Outlook, Gmail, etc.)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Nova pesquisa revela ataques baseados em CSS que escapam do conteúdo de e-mail para sequestrar interfaces de webmail, roubando credenciais e tokens em grandes provedores.

{{< cyber-report severity="High" source="The Hacker News" target="Interfaces de webmail (Outlook, Gmail, etc.)" >}}

O pesquisador de segurança Gareth, da PortSwigger, descobriu uma nova classe de ataques que usam CSS para quebrar o isolamento pretendido entre o conteúdo do e-mail e a interface do webmail ao redor. Ao criar e-mails maliciosos, um atacante pode fazer com que o conteúdo escape de sua fronteira de mensagem e interfira na interface do próprio webmail, potencialmente capturando senhas, roubando tokens de sessão e sequestrando ações confiáveis do usuário.

{{< ad-banner >}}

A pesquisa demonstra cadeias de ataque que afetam grandes provedores de webmail, incluindo Outlook, Gmail, Fastmail, Proton Mail, Yahoo Mail e AOL Mail. Além do roubo de credenciais, as técnicas podem ser usadas para assumir contas de terceiros, vazar tokens sensíveis e até manipular ferramentas de IA que leem e-mails, expandindo significativamente a superfície de ataque.

Essas descobertas destacam uma fraqueza fundamental na forma como os clientes de webmail renderizam conteúdo não confiável. Embora nenhum CVE específico tenha sido atribuído ainda, o impacto é severo, e organizações que dependem de webmail devem monitorar atualizações e considerar camadas adicionais de segurança para mitigar possíveis explorações.

{{< netrunner-insight >}}

Esta pesquisa ressalta que o e-mail não é apenas um vetor para malware, mas também pode ser uma arma contra a própria interface em que os usuários confiam. Analistas de SOC devem tratar e-mails suspeitos como possíveis payloads de quebra de interface, não apenas iscas de phishing. Equipes de DevSecOps devem revisar como seus clientes de webmail isolam conteúdo e considerar a aplicação de cabeçalhos de Política de Segurança de Conteúdo (CSP) estritos para limitar tentativas de fuga baseadas em CSS.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html)**
