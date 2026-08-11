---
title: "Ataque à Cadeia de Suprimentos da BdThemes Cria Administradores WordPress Rogue"
date: "2026-08-11T08:10:19Z"
original_date: "2026-08-11T05:48:44"
lang: "pt"
translationKey: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
slug: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
author: "NewsBot (Validated by Federico Sella)"
description: "Comprometimento da cadeia de suprimentos atinge plugins WordPress da BdThemes; nenhum código-fonte foi modificado, mas JSON malicioso cria contas de administrador rogue."
original_url: "https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html"
source: "The Hacker News"
severity: "High"
target: "Sites WordPress que usam plugins BdThemes"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Comprometimento da cadeia de suprimentos atinge plugins WordPress da BdThemes; nenhum código-fonte foi modificado, mas JSON malicioso cria contas de administrador rogue.

{{< cyber-report severity="High" source="The Hacker News" target="Sites WordPress que usam plugins BdThemes" >}}

Pesquisadores de segurança cibernética divulgaram um ataque à cadeia de suprimentos direcionado à BdThemes, um fornecedor de plugins WordPress. O comprometimento levou à desativação temporária dos downloads de plugins pela equipe de plugins do WordPress. Notavelmente, o ataque se desvia dos incidentes típicos de cadeia de suprimentos: nenhum arquivo de código-fonte no repositório oficial do WordPress.org foi modificado.

{{< ad-banner >}}

Em vez disso, o ataque utiliza payloads JSON maliciosos para criar contas de administrador WordPress rogue. Essa técnica permite que os atacantes obtenham acesso não autorizado a sites afetados sem alterar os arquivos principais do plugin, tornando a detecção mais desafiadora para verificações de integridade padrão.

O pesquisador da Wordfence, Paolo Tresso, destacou a natureza incomum do ataque, enfatizando que a ausência de modificações no código-fonte ressalta a necessidade de monitoramento abrangente da cadeia de suprimentos além da integridade do código.

{{< netrunner-insight >}}

Este ataque ressalta a importância de monitorar não apenas mudanças no código, mas também arquivos de configuração e dados como JSON. Para analistas de SOC, trate atualizações de plugins como eventos de alto risco e verifique a integridade de todos os arquivos, não apenas do código-fonte. DevSecOps deve implementar monitoramento em tempo de execução para criação inesperada de contas de administrador e considerar monitoramento de integridade de arquivos que cubra ativos não relacionados a código.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html)**
