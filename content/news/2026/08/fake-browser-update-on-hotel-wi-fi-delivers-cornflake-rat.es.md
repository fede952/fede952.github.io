---
title: "Falsa Actualización de Navegador en el Wi-Fi del Hotel Distribuye el RAT CornFlake"
date: "2026-08-01T09:04:02Z"
original_date: "2026-08-01T06:29:05"
lang: "es"
translationKey: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
slug: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft advierte sobre la operación CaptiveCrunch que utiliza el Wi-Fi secuestrado de hoteles para impulsar actualizaciones falsas y distribuir el malware de vigilancia CornFlake."
original_url: "https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html"
source: "The Hacker News"
severity: "High"
target: "Usuarios de Wi-Fi en hoteles"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft advierte sobre la operación CaptiveCrunch que utiliza el Wi-Fi secuestrado de hoteles para impulsar actualizaciones falsas y distribuir el malware de vigilancia CornFlake.

{{< cyber-report severity="High" source="The Hacker News" target="Usuarios de Wi-Fi en hoteles" >}}

Microsoft ha revelado una nueva campaña rastreada como CaptiveCrunch, que aprovecha las redes Wi-Fi secuestradas de hoteles para servir actualizaciones falsas de navegador. Estas actualizaciones son en realidad un troyano de acceso remoto (RAT) llamado CornFlake, capaz de capturar imágenes de la cámara web, audio del micrófono y pulsaciones de teclado, convirtiendo efectivamente los dispositivos infectados en herramientas de vigilancia.

{{< ad-banner >}}

La operación se atribuye a Storm-2945, que Microsoft evalúa como un subclúster operativo del conocido grupo de amenazas Midnight Blizzard. Esto sugiere un alto nivel de sofisticación y recursos, ya que la cadena de ataque implica comprometer la infraestructura de red de los hoteles para interceptar y redirigir el tráfico de los usuarios a páginas de actualización maliciosas.

Aunque el informe no especifica un CVE o una puntuación CVSS particular, el vector de ataque es notable por su uso de un entorno confiable (Wi-Fi de hotel) para distribuir malware. Los viajeros y profesionales de negocios están particularmente en riesgo, ya que a menudo dependen del Wi-Fi público y pueden ser más propensos a aceptar avisos de actualización del navegador sin escrutinio.

{{< netrunner-insight >}}

Esta campaña subraya la importancia de tratar cualquier aviso de actualización del navegador en redes no confiables con sospecha. Los analistas de SOC deben monitorear conexiones salientes inusuales desde endpoints que se hayan conectado recientemente a Wi-Fi de hoteles o público, y considerar bloquear o marcar dominios relacionados con actualizaciones que no estén en la lista de permitidos de la organización. Para DevSecOps, aplicar políticas de actualización estrictas y usar VPN de nivel empresarial para trabajadores remotos puede mitigar el riesgo de este tipo de ataques de watering hole.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html)**
