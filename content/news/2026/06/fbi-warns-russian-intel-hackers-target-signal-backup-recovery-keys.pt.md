---
title: "FBI Alerta que Hackers da Inteligência Russa Visam Chaves de Recuperação de Backup do Signal"
date: "2026-06-28T09:57:31Z"
original_date: "2026-06-26T19:38:29"
lang: "pt"
translationKey: "fbi-warns-russian-intel-hackers-target-signal-backup-recovery-keys"
author: "NewsBot (Validated by Federico Sella)"
description: "FBI e CISA atualizam alerta: phishing da inteligência russa agora rouba Chaves de Recuperação de Backup do Signal para ler mensagens privadas e assumir contas."
original_url: "https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html"
source: "The Hacker News"
severity: "High"
target: "Usuários do Signal"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

FBI e CISA atualizam alerta: phishing da inteligência russa agora rouba Chaves de Recuperação de Backup do Signal para ler mensagens privadas e assumir contas.

{{< cyber-report severity="High" source="The Hacker News" target="Usuários do Signal" >}}

O FBI e a CISA atualizaram seu alerta de março sobre campanhas de phishing da inteligência russa visando contas do Signal. Os atacantes adicionaram uma nova etapa: agora eles induzem as vítimas a fornecer sua Chave de Recuperação de Backup do Signal. Uma vez obtida, a chave permite que o atacante restaure o backup da conta, leia o histórico de mensagens privadas e de grupo, e assuma totalmente a conta.

{{< ad-banner >}}

A chave permanece válida mesmo após o comprometimento inicial, permitindo acesso persistente. Essa técnica contorna a autenticação de dois fatores tradicional, pois a chave de recuperação foi projetada para restauração legítima de conta. O comunicado enfatiza que os usuários nunca devem compartilhar sua chave de recuperação e devem ativar o bloqueio de registro e outros recursos de segurança.

As organizações devem educar os usuários sobre esse vetor específico de phishing e considerar a implementação de etapas adicionais de verificação para comunicações sensíveis. A ameaça é atribuída a atores da inteligência russa, destacando o contexto geopolítico da campanha.

{{< netrunner-insight >}}

Este é um exemplo clássico de engenharia social visando um recurso de segurança. Analistas de SOC devem monitorar solicitações incomuns de recuperação de conta e educar os usuários de que a Chave de Recuperação de Backup do Signal nunca deve ser compartilhada. Equipes de DevSecOps devem considerar a integração de autenticação resistente a phishing para comunicações críticas.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html)**
