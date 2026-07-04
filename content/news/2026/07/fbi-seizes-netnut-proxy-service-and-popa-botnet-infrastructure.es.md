---
title: "El FBI se incauta del servicio de proxy NetNut y de la infraestructura del botnet Popa"
date: "2026-07-04T09:20:04Z"
original_date: "2026-07-02T19:27:33"
lang: "es"
translationKey: "fbi-seizes-netnut-proxy-service-and-popa-botnet-infrastructure"
author: "NewsBot (Validated by Federico Sella)"
description: "El FBI ha incautado dominios vinculados a NetNut, un servicio de proxy residencial asociado al botnet Popa de 2 millones de dispositivos comprometidos, tras una investigación periodística."
original_url: "https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/"
source: "Krebs on Security"
severity: "High"
target: "Servicio de proxy residencial NetNut y botnet Popa"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

El FBI ha incautado dominios vinculados a NetNut, un servicio de proxy residencial asociado al botnet Popa de 2 millones de dispositivos comprometidos, tras una investigación periodística.

{{< cyber-report severity="High" source="Krebs on Security" target="Servicio de proxy residencial NetNut y botnet Popa" >}}

El FBI, en coordinación con socios de la industria, ha incautado cientos de dominios asociados a NetNut, un servicio de proxy residencial operado por la empresa israelí que cotiza en bolsa Alarum Technologies (NASDAQ: ALAR). La acción sigue a un informe de KrebsOnSecurity que vinculaba a NetNut con el botnet Popa, una red de al menos dos millones de dispositivos comprometidos sin el consentimiento del usuario.

{{< ad-banner >}}

El botnet Popa aprovecha dispositivos infectados para enrutar el tráfico a través de la infraestructura de proxy de NetNut, facilitando actividades maliciosas como el relleno de credenciales, el fraude publicitario y la toma de cuentas. La incautación interrumpe tanto el servicio de proxy como las capacidades de comando y control del botnet.

Esta operación resalta la tendencia creciente de las fuerzas del orden a atacar servicios de proxy que facilitan el cibercrimen. Las organizaciones deben revisar su tráfico de red en busca de conexiones a dominios incautados y monitorear la actividad residual del botnet.

{{< netrunner-insight >}}

Para los analistas de SOC, esta desarticulación subraya la importancia de monitorear los rangos de IP de proxy residencial en las fuentes de inteligencia de amenazas. Los equipos de DevSecOps deben auditar cualquier integración con servicios de proxy de terceros y asegurarse de contar con mecanismos robustos de detección de botnets, ya que los remanentes de Popa pueden persistir en infraestructura alternativa.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en Krebs on Security ›](https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/)**
