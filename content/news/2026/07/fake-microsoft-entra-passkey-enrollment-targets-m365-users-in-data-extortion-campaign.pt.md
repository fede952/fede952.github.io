---
title: "Falso Cadastro de Passkey do Microsoft Entra Visa Usuários do M365 em Campanha de Extorsão de Dados"
date: "2026-07-12T09:00:42Z"
original_date: "2026-07-10T10:30:20"
lang: "pt"
translationKey: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
slug: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "O ator de ameaças O-UNC-066 usa phishing baseado em voz para enganar usuários e fazê-los cadastrar uma passkey falsa do Entra, visando comprometer contas do Microsoft 365 para extorsão de dados."
original_url: "https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html"
source: "The Hacker News"
severity: "High"
target: "Usuários do Microsoft 365"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

O ator de ameaças O-UNC-066 usa phishing baseado em voz para enganar usuários e fazê-los cadastrar uma passkey falsa do Entra, visando comprometer contas do Microsoft 365 para extorsão de dados.

{{< cyber-report severity="High" source="The Hacker News" target="Usuários do Microsoft 365" >}}

Um ator de ameaças rastreado como O-UNC-066 pela Okta foi observado realizando ataques de phishing baseados em voz direcionados a usuários do Microsoft 365 em vários setores. Os atacantes se passam por solicitações legítimas de segurança para enganar as vítimas e fazê-las cadastrar uma passkey falsa do Entra, concedendo assim ao adversário acesso não autorizado às suas contas.

{{< ad-banner >}}

A campanha utiliza um kit de phishing controlado por painel, projetado especificamente para interceptar o processo de cadastro da passkey. Uma vez que o atacante obtém acesso, ele visa realizar extorsão de dados, exfiltrando informações sensíveis e exigindo resgate. Os ataques destacam uma tendência crescente de uso de canais de voz para contornar as defesas tradicionais de phishing por e-mail.

As organizações são aconselhadas a implementar autenticação multifator (MFA) com chaves de segurança de hardware e a educar os usuários sobre a verificação de qualquer solicitação de segurança não solicitada por meio de canais de comunicação alternativos. Monitorar atividades anômalas de cadastro de passkey pode ajudar a detectar tais ataques precocemente.

{{< netrunner-insight >}}

Este ataque ressalta a importância de tratar solicitações de segurança baseadas em voz com o mesmo ceticismo que e-mails de phishing. Analistas de SOC devem monitorar tentativas incomuns de cadastro de passkey e garantir que os processos de cadastro de MFA exijam verificação fora da banda. Equipes de DevSecOps devem considerar a implementação de políticas de acesso condicional que restrinjam o cadastro de passkey a dispositivos e locais confiáveis.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html)**
