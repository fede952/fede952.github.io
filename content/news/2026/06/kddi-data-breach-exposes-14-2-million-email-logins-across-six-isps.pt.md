---
title: "Vazamento de dados da KDDI expõe 14,2 milhões de logins de e-mail em seis ISPs"
date: "2026-06-29T11:56:07Z"
original_date: "2026-06-28T14:13:46"
lang: "pt"
translationKey: "kddi-data-breach-exposes-14-2-million-email-logins-across-six-isps"
author: "NewsBot (Validated by Federico Sella)"
description: "A operadora japonesa KDDI divulga violação do sistema de e-mail que afeta outros cinco ISPs, comprometendo até 14,2 milhões de credenciais de usuários."
original_url: "https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/"
source: "BleepingComputer"
severity: "High"
target: "Sistemas de e-mail de ISPs japoneses"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A operadora japonesa KDDI divulga violação do sistema de e-mail que afeta outros cinco ISPs, comprometendo até 14,2 milhões de credenciais de usuários.

{{< cyber-report severity="High" source="BleepingComputer" target="Sistemas de e-mail de ISPs japoneses" >}}

A operadora de telecomunicações japonesa KDDI Corporation divulgou uma violação de dados na qual atores de ameaças obtiveram acesso a um de seus sistemas de e-mail usado por outros cinco provedores de serviços de internet (ISPs) no país. A violação potencialmente expôs até 14,2 milhões de logins de e-mail, impactando um número significativo de usuários em vários provedores.

{{< ad-banner >}}

O sistema comprometido faz parte da infraestrutura de e-mail da KDDI, que serve como backend para vários ISPs. Embora o método exato de invasão não tenha sido detalhado, o incidente ressalta os riscos inerentes às arquiteturas de provedores de serviços compartilhados, onde um único ponto de falha pode se propagar por várias organizações.

A KDDI notificou os ISPs afetados e está trabalhando para conter a violação. Os usuários são aconselhados a alterar senhas e ativar a autenticação multifator quando disponível. O incidente destaca a necessidade de segmentação robusta e monitoramento de componentes de infraestrutura compartilhada.

{{< netrunner-insight >}}

Esta violação é um exemplo clássico de risco de cadeia de suprimentos em ecossistemas de ISP. Analistas de SOC devem priorizar o monitoramento de movimentação lateral de sistemas de e-mail para outros ativos críticos, enquanto equipes de DevSecOps devem impor segmentação de rede rigorosa e acesso com privilégios mínimos para serviços de backend compartilhados. Espere ataques de preenchimento de credenciais visando essas contas expostas nas próximas semanas.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/)**
