---
title: "Tokens de Autenticação do OpenAI Codex Roubados em Ataque à Cadeia de Suprimentos do npm"
date: "2026-06-01T12:34:23Z"
original_date: "2026-06-01T09:31:15"
lang: "pt"
translationKey: "openai-codex-auth-tokens-stolen-in-npm-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Pacote npm malicioso codexui-android tem como alvo desenvolvedores, roubando tokens de autenticação do OpenAI Codex com mais de 29.000 downloads semanais."
original_url: "https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html"
source: "The Hacker News"
severity: "High"
target: "Desenvolvedores do OpenAI Codex"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Pacote npm malicioso codexui-android tem como alvo desenvolvedores, roubando tokens de autenticação do OpenAI Codex com mais de 29.000 downloads semanais.

{{< cyber-report severity="High" source="The Hacker News" target="Desenvolvedores do OpenAI Codex" >}}

Pesquisadores de cibersegurança descobriram uma campanha maliciosa na cadeia de suprimentos visando desenvolvedores que usam o OpenAI Codex. O ataque utiliza um pacote npm de aparência legítima chamado codexui-android, que é anunciado como uma interface web remota para o OpenAI Codex tanto no GitHub quanto no npm. O pacote atraiu mais de 29.000 downloads semanais, indicando alcance significativo na comunidade de desenvolvedores.

{{< ad-banner >}}

O pacote malicioso foi projetado para roubar tokens de autenticação do OpenAI Codex de desenvolvedores desavisados. Até o momento do relatório, o pacote permanece disponível para download, representando uma ameaça contínua. Desenvolvedores que instalaram codexui-android são aconselhados a rotacionar seus tokens imediatamente e auditar seus sistemas em busca de acesso não autorizado.

Este incidente destaca o risco persistente de ataques à cadeia de suprimentos no ecossistema de código aberto. O uso de nomes de pacotes com som legítimo e altas contagens de downloads pode levar os desenvolvedores a uma falsa sensação de segurança. As organizações devem implementar processos rigorosos de verificação de pacotes e considerar o uso de ferramentas que detectem comportamento anômalo de pacotes.

{{< netrunner-insight >}}

Para analistas de SOC e engenheiros DevSecOps, este ataque ressalta a necessidade de monitorar downloads e comportamento de pacotes npm. Implemente detecção em tempo de execução para exfiltração inesperada de tokens e aplique acesso com privilégios mínimos para tokens de API. Audite regularmente sua cadeia de suprimentos de software e considere o uso de ferramentas de verificação de integridade de pacotes.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html)**
