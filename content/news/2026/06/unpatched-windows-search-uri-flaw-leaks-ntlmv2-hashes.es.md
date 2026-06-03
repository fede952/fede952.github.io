---
title: "Fallo sin parche en el controlador URI de búsqueda de Windows filtra hashes NTLMv2"
date: "2026-06-03T11:53:18Z"
original_date: "2026-06-03T10:18:52"
lang: "es"
translationKey: "unpatched-windows-search-uri-flaw-leaks-ntlmv2-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "Investigadores revelan una vulnerabilidad sin parche en el controlador URI de búsqueda de Windows que puede exponer hashes NTLMv2, similar al fallo CVE-2026-33829 de la herramienta de recorte."
original_url: "https://thehackernews.com/2026/06/unpatched-windows-search-uri.html"
source: "The Hacker News"
severity: "High"
target: "Controlador URI de búsqueda de Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Investigadores revelan una vulnerabilidad sin parche en el controlador URI de búsqueda de Windows que puede exponer hashes NTLMv2, similar al fallo CVE-2026-33829 de la herramienta de recorte.

{{< cyber-report severity="High" source="The Hacker News" target="Controlador URI de búsqueda de Windows" >}}

Investigadores de ciberseguridad de Huntress han revelado detalles de una vulnerabilidad sin parche en el controlador URI de búsqueda de Windows que podría permitir a atacantes robar hashes NTLMv2. El problema recuerda a CVE-2026-33829, una vulnerabilidad de suplantación en el controlador URI ms-screensketch de la herramienta de recorte de Windows que también exponía hashes NTLM.

{{< ad-banner >}}

El fallo recién identificado reside en el esquema URI search:, que se utiliza para lanzar consultas de búsqueda de Windows. Al crear un enlace o archivo malicioso que active el controlador URI search:, un atacante puede forzar al sistema objetivo a autenticarse en un servidor remoto, filtrando así el hash NTLMv2 del usuario. Este hash puede ser descifrado fuera de línea o utilizado en ataques de retransmisión.

Hasta la fecha de publicación, Microsoft no ha lanzado ningún parche oficial. Se recomienda a las organizaciones monitorear las actualizaciones y considerar bloquear el controlador URI search: mediante directivas de grupo o herramientas de seguridad de endpoints hasta que haya una solución disponible.

{{< netrunner-insight >}}

Este es un vector clásico de retransmisión NTLM que los analistas del SOC deben vigilar en los registros de autenticación. Los ingenieros de DevSecOps deben revisar inmediatamente cualquier uso de controladores URI en sus entornos y considerar aplicar mitigaciones como deshabilitar NTLMv2 o imponer la firma SMB. Hasta que Microsoft parchee esto, asuma que el URI search: es un posible punto de entrada para el robo de credenciales.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/06/unpatched-windows-search-uri.html)**
