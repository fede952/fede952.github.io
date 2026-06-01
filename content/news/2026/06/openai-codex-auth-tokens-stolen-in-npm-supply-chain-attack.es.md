---
title: "Tokens de autenticación de OpenAI Codex robados en un ataque a la cadena de suministro de npm"
date: "2026-06-01T12:34:23Z"
original_date: "2026-06-01T09:31:15"
lang: "es"
translationKey: "openai-codex-auth-tokens-stolen-in-npm-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "El paquete npm malicioso codexui-android ataca a desarrolladores, robando tokens de autenticación de OpenAI Codex con más de 29,000 descargas semanales."
original_url: "https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html"
source: "The Hacker News"
severity: "High"
target: "Desarrolladores de OpenAI Codex"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

El paquete npm malicioso codexui-android ataca a desarrolladores, robando tokens de autenticación de OpenAI Codex con más de 29,000 descargas semanales.

{{< cyber-report severity="High" source="The Hacker News" target="Desarrolladores de OpenAI Codex" >}}

Investigadores de ciberseguridad han descubierto una campaña maliciosa en la cadena de suministro dirigida a desarrolladores que usan OpenAI Codex. El ataque aprovecha un paquete npm de apariencia legítima llamado codexui-android, que se promociona como una interfaz web remota para OpenAI Codex tanto en GitHub como en npm. El paquete ha atraído más de 29,000 descargas semanales, lo que indica un alcance significativo dentro de la comunidad de desarrolladores.

{{< ad-banner >}}

El paquete malicioso está diseñado para robar tokens de autenticación de OpenAI Codex de desarrolladores desprevenidos. Hasta la fecha del informe, el paquete sigue disponible para su descarga, lo que representa una amenaza continua. Se recomienda a los desarrolladores que hayan instalado codexui-android que roten sus tokens inmediatamente y auditen sus sistemas en busca de accesos no autorizados.

Este incidente resalta el riesgo persistente de los ataques a la cadena de suministro en el ecosistema de código abierto. El uso de nombres de paquetes de sonido legítimo y un alto número de descargas puede adormecer a los desarrolladores en una falsa sensación de seguridad. Las organizaciones deben implementar procesos estrictos de revisión de paquetes y considerar el uso de herramientas que detecten comportamientos anómalos en los paquetes.

{{< netrunner-insight >}}

Para los analistas de SOC e ingenieros de DevSecOps, este ataque subraya la necesidad de monitorear las descargas y el comportamiento de los paquetes npm. Implemente detección en tiempo de ejecución para la exfiltración inesperada de tokens y aplique acceso de mínimo privilegio para los tokens de API. Audite regularmente su cadena de suministro de software y considere usar herramientas de verificación de integridad de paquetes.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html)**
