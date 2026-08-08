---
title: "Campanha de Phishing AitM Visa Microsoft 365 para Roubar E-mails Financeiros"
date: "2026-08-08T07:47:42Z"
original_date: "2026-08-07T10:38:27"
lang: "pt"
translationKey: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
slug: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
author: "NewsBot (Validated by Federico Sella)"
description: "Phishing generalizado por e-mail usa adversary-in-the-middle para sequestrar contas do Microsoft 365, com o objetivo de coletar e-mails de folha de pagamento e finanças."
original_url: "https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html"
source: "The Hacker News"
severity: "High"
target: "Contas do Microsoft 365"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Phishing generalizado por e-mail usa adversary-in-the-middle para sequestrar contas do Microsoft 365, com o objetivo de coletar e-mails de folha de pagamento e finanças.

{{< cyber-report severity="High" source="The Hacker News" target="Contas do Microsoft 365" >}}

Pesquisadores de segurança cibernética identificaram uma campanha de phishing ativa e generalizada por e-mail que utiliza técnicas de adversary-in-the-middle (AitM) para comprometer contas do Microsoft 365. O objetivo principal da campanha é identificar pessoal-chave envolvido em fluxos de trabalho financeiros e exfiltrar comunicações de e-mail relacionadas, particularmente aquelas referentes à folha de pagamento e finanças.

{{< ad-banner >}}

Os atacantes empregam proxies residenciais para disfarçar seus logins maliciosos como tráfego comum de consumidores, evitando assim a detecção por controles de segurança que normalmente sinalizam endereços IP suspeitos. Essa técnica permite que os atacantes mantenham persistência e acesso às contas comprometidas sem levantar alarmes imediatos.

Organizações que usam o Microsoft 365 devem estar vigilantes contra tais tentativas de phishing AitM, que frequentemente contornam a autenticação multifator ao retransmitir credenciais e tokens de sessão em tempo real. O foco da campanha em dados financeiros sugere um esforço direcionado para facilitar fraudes financeiras ou comprometimento de e-mail comercial (BEC).

{{< netrunner-insight >}}

Esta campanha ressalta a necessidade de MFA resistente a phishing, como chaves de segurança FIDO2, e monitoramento contínuo de logins anômalos, especialmente aqueles originados de faixas de IP residenciais. As equipes de SOC também devem priorizar regras de detecção para kits de ferramentas AitM e aplicar políticas de acesso condicional que restrinjam o acesso com base em sinais de risco. Engenheiros de DevSecOps devem considerar a implementação de vinculação de sessão e verificações de conformidade do dispositivo para mitigar ataques de retransmissão de token.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html)**
