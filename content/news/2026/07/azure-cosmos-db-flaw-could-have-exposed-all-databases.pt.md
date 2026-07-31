---
title: "Falha no Azure Cosmos DB Poderia Ter Exposto Todos os Bancos de Dados"
date: "2026-07-31T09:37:51Z"
original_date: "2026-07-30T13:34:09"
lang: "pt"
translationKey: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
slug: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
author: "NewsBot (Validated by Federico Sella)"
description: "Uma vulnerabilidade corrigida no Azure Cosmos DB permitia escape de sandbox e acesso entre locatários, descoberta pela Wiz como CosmosEscape."
original_url: "https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html"
source: "The Hacker News"
severity: "High"
target: "Azure Cosmos DB"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Uma vulnerabilidade corrigida no Azure Cosmos DB permitia escape de sandbox e acesso entre locatários, descoberta pela Wiz como CosmosEscape.

{{< cyber-report severity="High" source="The Hacker News" target="Azure Cosmos DB" >}}

Uma vulnerabilidade agora corrigida no Azure Cosmos DB poderia ter permitido a um atacante escapar do sandbox de consultas Gremlin do serviço e obter acesso total de leitura e escrita aos bancos de dados de locatários de clientes. A falha foi descoberta pela empresa de segurança Wiz, que codificou a cadeia de exploração como 'CosmosEscape'.

{{< ad-banner >}}

A cadeia de ataque começava com uma consulta elaborada contra um banco de dados Gremlin controlado pelo atacante. A partir daí, o atacante poderia alcançar a execução de código na infraestrutura subjacente, potencialmente comprometendo o isolamento entre locatários.

Embora a Microsoft tenha corrigido o problema desde então, o incidente ressalta a importância crítica do isolamento de locatários em serviços de banco de dados em nuvem. Organizações que usam o Azure Cosmos DB devem revisar suas configurações de segurança e monitorar qualquer atividade incomum.

{{< netrunner-insight >}}

Para analistas de SOC, isso destaca a necessidade de monitorar consultas Gremlin anômalas e padrões incomuns de acesso a banco de dados. As equipes de DevSecOps devem garantir que os serviços de banco de dados em nuvem sejam configurados com o princípio do menor privilégio e que quaisquer mecanismos de sandbox sejam auditados regularmente. Embora isso esteja corrigido, falhas semelhantes podem existir em outros serviços gerenciados, portanto, a caça proativa a ameaças é essencial.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html)**
