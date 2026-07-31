---
title: "Уязвимость в Azure Cosmos DB могла раскрыть все базы данных"
date: "2026-07-31T09:37:51Z"
original_date: "2026-07-30T13:34:09"
lang: "ru"
translationKey: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
slug: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
author: "NewsBot (Validated by Federico Sella)"
description: "Исправленная уязвимость в Azure Cosmos DB позволяла обойти песочницу и получить доступ к базам данных разных клиентов; обнаружена компанией Wiz под названием CosmosEscape."
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

Исправленная уязвимость в Azure Cosmos DB позволяла обойти песочницу и получить доступ к базам данных разных клиентов; обнаружена компанией Wiz под названием CosmosEscape.

{{< cyber-report severity="High" source="The Hacker News" target="Azure Cosmos DB" >}}

Исправленная уязвимость в Azure Cosmos DB могла позволить злоумышленнику обойти песочницу запросов Gremlin и получить полный доступ на чтение и запись к базам данных клиентов разных арендаторов. Ошибка была обнаружена компанией Wiz, которая назвала цепочку эксплойтов 'CosmosEscape'.

{{< ad-banner >}}

Цепочка атак начиналась с специально созданного запроса к базе данных Gremlin, контролируемой злоумышленником. Далее злоумышленник мог добиться выполнения кода на базовой инфраструктуре, что потенциально нарушало изоляцию между арендаторами.

Хотя Microsoft уже исправила проблему, инцидент подчеркивает критическую важность изоляции арендаторов в облачных сервисах баз данных. Организациям, использующим Azure Cosmos DB, следует пересмотреть свои конфигурации безопасности и отслеживать любую подозрительную активность.

{{< netrunner-insight >}}

Для аналитиков SOC это подчеркивает необходимость мониторинга аномальных запросов Gremlin и необычных паттернов доступа к базам данных. Команды DevSecOps должны обеспечивать настройку облачных сервисов баз данных с принципом минимальных привилегий и регулярно проверять механизмы песочницы. Хотя эта уязвимость исправлена, аналогичные ошибки могут существовать в других управляемых сервисах, поэтому упреждающий поиск угроз необходим.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html)**
