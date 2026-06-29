---
title: "Filtración de datos de KDDI expone 14.2 millones de inicios de sesión de correo electrónico en seis ISP"
date: "2026-06-29T11:56:07Z"
original_date: "2026-06-28T14:13:46"
lang: "es"
translationKey: "kddi-data-breach-exposes-14-2-million-email-logins-across-six-isps"
author: "NewsBot (Validated by Federico Sella)"
description: "El operador japonés KDDI revela una brecha en su sistema de correo electrónico que afecta a otros cinco ISP, comprometiendo hasta 14.2 millones de credenciales de usuarios."
original_url: "https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/"
source: "BleepingComputer"
severity: "High"
target: "Sistemas de correo electrónico de ISP japoneses"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

El operador japonés KDDI revela una brecha en su sistema de correo electrónico que afecta a otros cinco ISP, comprometiendo hasta 14.2 millones de credenciales de usuarios.

{{< cyber-report severity="High" source="BleepingComputer" target="Sistemas de correo electrónico de ISP japoneses" >}}

El operador de telecomunicaciones japonés KDDI Corporation reveló una filtración de datos en la que actores de amenazas obtuvieron acceso a uno de sus sistemas de correo electrónico utilizado por otros cinco proveedores de servicios de internet (ISP) en el país. La brecha potencialmente expuso hasta 14.2 millones de inicios de sesión de correo electrónico, afectando a un número significativo de usuarios en múltiples proveedores.

{{< ad-banner >}}

El sistema comprometido forma parte de la infraestructura de correo electrónico de KDDI, que sirve como backend para varios ISP. Aunque no se ha detallado el método exacto de intrusión, el incidente subraya los riesgos inherentes a las arquitecturas de proveedores de servicios compartidos, donde un único punto de fallo puede afectar en cascada a múltiples organizaciones.

KDDI ha notificado a los ISP afectados y está trabajando para contener la brecha. Se recomienda a los usuarios cambiar las contraseñas y habilitar la autenticación multifactor donde esté disponible. El incidente resalta la necesidad de una segmentación robusta y monitoreo de los componentes de infraestructura compartida.

{{< netrunner-insight >}}

Esta brecha es un ejemplo clásico de riesgo en la cadena de suministro en ecosistemas de ISP. Los analistas del SOC deben priorizar el monitoreo de movimientos laterales desde los sistemas de correo electrónico hacia otros activos críticos, mientras que los equipos de DevSecOps deben imponer una estricta segmentación de red y acceso con privilegios mínimos para los servicios backend compartidos. Espere ataques de relleno de credenciales dirigidos a estas cuentas expuestas en las próximas semanas.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/)**
