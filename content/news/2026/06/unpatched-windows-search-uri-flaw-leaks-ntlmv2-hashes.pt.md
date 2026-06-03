---
title: "Falha não corrigida no manipulador de URI search do Windows vaza hashes NTLMv2"
date: "2026-06-03T11:53:18Z"
original_date: "2026-06-03T10:18:52"
lang: "pt"
translationKey: "unpatched-windows-search-uri-flaw-leaks-ntlmv2-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "Pesquisadores divulgam uma vulnerabilidade não corrigida no manipulador de URI search: do Windows que pode expor hashes NTLMv2, semelhante à falha CVE-2026-33829 na Ferramenta de Recorte."
original_url: "https://thehackernews.com/2026/06/unpatched-windows-search-uri.html"
source: "The Hacker News"
severity: "High"
target: "Manipulador de URI search: do Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Pesquisadores divulgam uma vulnerabilidade não corrigida no manipulador de URI search: do Windows que pode expor hashes NTLMv2, semelhante à falha CVE-2026-33829 na Ferramenta de Recorte.

{{< cyber-report severity="High" source="The Hacker News" target="Manipulador de URI search: do Windows" >}}

Pesquisadores de cibersegurança da Huntress divulgaram detalhes de uma vulnerabilidade não corrigida no manipulador de URI search: do Windows que pode permitir que atacantes roubem hashes NTLMv2. O problema é reminiscente do CVE-2026-33829, uma vulnerabilidade de falsificação no manipulador de URI ms-screensketch: da Ferramenta de Recorte do Windows que também expunha hashes NTLM.

{{< ad-banner >}}

A falha recém-identificada reside no esquema de URI search:, usado para iniciar consultas de Pesquisa do Windows. Ao criar um link ou arquivo malicioso que aciona o manipulador de URI search:, um atacante pode forçar o sistema alvo a autenticar em um servidor remoto, vazando assim o hash NTLMv2 do usuário. Esse hash pode então ser quebrado offline ou usado em ataques de relay.

Até a data de publicação, nenhum patch oficial foi lançado pela Microsoft. As organizações são aconselhadas a monitorar atualizações e considerar bloquear o manipulador de URI search: via política de grupo ou ferramentas de segurança de endpoint até que uma correção esteja disponível.

{{< netrunner-insight >}}

Este é um vetor clássico de relay NTLM que analistas de SOC devem observar nos logs de autenticação. Engenheiros de DevSecOps devem revisar imediatamente qualquer uso de manipuladores de URI em seus ambientes e considerar aplicar mitigações como desabilitar NTLMv2 ou impor assinatura SMB. Até que a Microsoft corrija isso, considere o URI search: como um possível ponto de entrada para roubo de credenciais.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/06/unpatched-windows-search-uri.html)**
