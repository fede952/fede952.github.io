---
title: "Los ataques CSS escapan de los límites del correo electrónico para robar contraseñas y tokens"
date: "2026-08-09T07:52:16Z"
original_date: "2026-08-08T08:03:57"
lang: "es"
translationKey: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
slug: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Una nueva investigación revela ataques basados en CSS que salen del contenido del correo electrónico para secuestrar las interfaces de webmail, robando credenciales y tokens en los principales proveedores."
original_url: "https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html"
source: "The Hacker News"
severity: "High"
target: "Interfaces de webmail (Outlook, Gmail, etc.)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una nueva investigación revela ataques basados en CSS que salen del contenido del correo electrónico para secuestrar las interfaces de webmail, robando credenciales y tokens en los principales proveedores.

{{< cyber-report severity="High" source="The Hacker News" target="Interfaces de webmail (Outlook, Gmail, etc.)" >}}

El investigador de seguridad Gareth de PortSwigger ha descubierto una nueva clase de ataques que aprovechan CSS para romper el aislamiento previsto entre el contenido del correo electrónico y la interfaz de webmail circundante. Al crear correos electrónicos maliciosos, un atacante puede hacer que el contenido escape de su límite de mensaje e interfiera con la interfaz de usuario del propio webmail, pudiendo capturar contraseñas, robar tokens de sesión y secuestrar acciones de usuario confiables.

{{< ad-banner >}}

La investigación demuestra cadenas de ataque que afectan a los principales proveedores de webmail, incluidos Outlook, Gmail, Fastmail, Proton Mail, Yahoo Mail y AOL Mail. Más allá del robo de credenciales, las técnicas se pueden utilizar para tomar el control de cuentas de terceros, filtrar tokens sensibles e incluso manipular herramientas de IA que leen correos electrónicos, ampliando significativamente la superficie de ataque.

Estos hallazgos resaltan una debilidad fundamental en cómo los clientes de webmail renderizan contenido no confiable. Si bien aún no se ha asignado ningún CVE específico, el impacto es grave, y las organizaciones que dependen del webmail deben monitorear las actualizaciones y considerar capas de seguridad adicionales para mitigar una posible explotación.

{{< netrunner-insight >}}

Esta investigación subraya que el correo electrónico no es solo un vector para malware, sino que también puede ser un arma contra la propia interfaz en la que los usuarios confían. Los analistas del SOC deben tratar los correos electrónicos sospechosos como posibles cargas útiles que rompen la interfaz de usuario, no solo como señuelos de phishing. Los equipos de DevSecOps deben revisar cómo sus clientes de webmail aíslan el contenido y considerar la aplicación de encabezados de Política de Seguridad de Contenido (CSP) estrictos para limitar los intentos de fuga basados en CSS.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html)**
