---
title: "Brecha de OAuth en Klue: Hackers Icarus Roban Tokens de Salesforce"
date: "2026-06-20T09:59:52Z"
original_date: "2026-06-19T22:31:04"
lang: "es"
translationKey: "klue-oauth-breach-icarus-hackers-steal-salesforce-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Klue confirma el robo de tokens OAuth que afecta integraciones de Salesforce; el grupo de extorsión Icarus se atribuye la responsabilidad y la lista de víctimas crece."
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/"
source: "BleepingComputer"
severity: "High"
target: "plataforma de inteligencia de mercado Klue"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Klue confirma el robo de tokens OAuth que afecta integraciones de Salesforce; el grupo de extorsión Icarus se atribuye la responsabilidad y la lista de víctimas crece.

{{< cyber-report severity="High" source="BleepingComputer" target="plataforma de inteligencia de mercado Klue" >}}

La plataforma de inteligencia de mercado Klue ha confirmado un incidente de seguridad en el que actores maliciosos robaron tokens OAuth utilizados para conectar con los entornos de Salesforce de los clientes. La brecha, reivindicada por el grupo de extorsión recién surgido 'Icarus', ha llevado a una lista creciente de víctimas afectadas.

{{< ad-banner >}}

Los tokens OAuth robados podrían permitir a los atacantes acceder a datos de Salesforce sin requerir autenticación adicional, lo que representa un riesgo significativo para los clientes de Klue. El incidente resalta los peligros de la exposición de tokens OAuth y la necesidad de una gestión robusta del ciclo de vida de los tokens.

Mientras el grupo Icarus reclama públicamente el ataque, las organizaciones que utilizan la integración de Salesforce de Klue deberían revocar y rotar inmediatamente cualquier token OAuth asociado y monitorear accesos no autorizados. El alcance total de la brecha aún está bajo investigación.

{{< netrunner-insight >}}

Este incidente subraya la importancia crítica de asegurar los tokens OAuth como credenciales sensibles. Los analistas del SOC deben priorizar la monitorización de llamadas anómalas a la API de Salesforce y aplicar políticas de expiración de tokens. Los equipos de DevSecOps deben implementar mecanismos estrictos de alcance y rotación de tokens para limitar el radio de explosión en caso de compromiso.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/)**
