---
title: "La falla de Azure Cosmos DB podría haber expuesto todas las bases de datos"
date: "2026-07-31T09:37:51Z"
original_date: "2026-07-30T13:34:09"
lang: "es"
translationKey: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
slug: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
author: "NewsBot (Validated by Federico Sella)"
description: "Una vulnerabilidad parcheada de Azure Cosmos DB permitía el escape del sandbox y el acceso a bases de datos entre inquilinos, descubierta por Wiz como CosmosEscape."
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

Una vulnerabilidad parcheada de Azure Cosmos DB permitía el escape del sandbox y el acceso a bases de datos entre inquilinos, descubierta por Wiz como CosmosEscape.

{{< cyber-report severity="High" source="The Hacker News" target="Azure Cosmos DB" >}}

Una vulnerabilidad ahora parcheada en Azure Cosmos DB podría haber permitido a un atacante escapar del sandbox de consultas Gremlin del servicio y obtener acceso completo de lectura y escritura a bases de datos en todos los inquilinos de clientes. La falla fue descubierta por la firma de seguridad Wiz, que denominó a la cadena de explotación 'CosmosEscape'.

{{< ad-banner >}}

La cadena de ataque comenzaba con una consulta manipulada contra una base de datos Gremlin controlada por el atacante. A partir de ahí, el atacante podía lograr la ejecución de código en la infraestructura subyacente, comprometiendo potencialmente el aislamiento entre inquilinos.

Aunque Microsoft ha parcheado el problema desde entonces, el incidente subraya la importancia crítica del aislamiento de inquilinos en los servicios de bases de datos en la nube. Las organizaciones que utilizan Azure Cosmos DB deben revisar sus configuraciones de seguridad y monitorear cualquier actividad inusual.

{{< netrunner-insight >}}

Para los analistas del SOC, esto resalta la necesidad de monitorear consultas Gremlin anómalas y patrones de acceso a bases de datos inusuales. Los equipos de DevSecOps deben asegurarse de que los servicios de bases de datos en la nube estén configurados con el principio de privilegio mínimo y que cualquier mecanismo de sandboxing se audite regularmente. Aunque esto ya está parcheado, pueden existir fallas similares en otros servicios administrados, por lo que la búsqueda proactiva de amenazas es esencial.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html)**
