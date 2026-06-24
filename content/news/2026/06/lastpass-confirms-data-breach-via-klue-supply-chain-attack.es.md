---
title: "LastPass confirma una filtración de datos a través del ataque a la cadena de suministro de Klue"
date: "2026-06-24T10:23:36Z"
original_date: "2026-06-23T13:58:25"
lang: "es"
translationKey: "lastpass-confirms-data-breach-via-klue-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "LastPass reveló que atacantes robaron tokens OAuth de una aplicación de terceros, Klue, para acceder a datos de clientes en su entorno de Salesforce."
original_url: "https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Entorno de Salesforce de LastPass"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

LastPass reveló que atacantes robaron tokens OAuth de una aplicación de terceros, Klue, para acceder a datos de clientes en su entorno de Salesforce.

{{< cyber-report severity="High" source="BleepingComputer" target="Entorno de Salesforce de LastPass" >}}

LastPass ha confirmado que hackers accedieron a datos de clientes de su entorno de Salesforce después de robar los tokens OAuth de la empresa en el ataque a la cadena de suministro de Klue a principios de este mes. La filtración, revelada el 23 de junio de 2026, resalta los riesgos de las integraciones de terceros y el robo de tokens.

{{< ad-banner >}}

Los atacantes utilizaron tokens OAuth comprometidos de Klue, una aplicación de terceros, para obtener acceso no autorizado a la instancia de Salesforce de LastPass. Este ataque a la cadena de suministro permitió a los actores de amenazas exfiltrar datos de clientes sin activar las alertas de autenticación típicas.

LastPass está notificando a los clientes afectados y ha revocado los tokens comprometidos. La compañía también está revisando sus políticas de acceso de terceros para prevenir incidentes similares. Esta filtración subraya la importancia de monitorear el uso de tokens OAuth e implementar controles de acceso estrictos para servicios integrados.

{{< netrunner-insight >}}

Este incidente es un ejemplo clásico de riesgo en la cadena de suministro mediante el abuso de tokens OAuth. Los analistas del SOC deben priorizar la monitorización de uso anómalo de tokens e implementar políticas de caducidad de tokens. Los equipos de DevSecOps deben aplicar el principio de mínimo privilegio para las integraciones de terceros y considerar el uso de tokens de corta duración para reducir el radio de explosión.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/)**
