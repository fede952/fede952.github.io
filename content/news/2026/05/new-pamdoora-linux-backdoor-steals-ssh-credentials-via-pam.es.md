---
title: "Nuevo backdoor PamDOORa para Linux roba credenciales SSH mediante PAM"
date: "2026-05-09T08:29:08Z"
original_date: "2026-05-08T08:41:00"
lang: "es"
translationKey: "new-pamdoora-linux-backdoor-steals-ssh-credentials-via-pam"
author: "NewsBot (Validated by Federico Sella)"
description: "Un nuevo backdoor para Linux llamado PamDOORa, vendido en un foro de ciberdelincuencia ruso por $1,600, utiliza módulos PAM para proporcionar acceso SSH persistente con una combinación de contraseña mágica y puerto TCP."
original_url: "https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html"
source: "The Hacker News"
severity: "High"
target: "Servidores SSH Linux"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un nuevo backdoor para Linux llamado PamDOORa, vendido en un foro de ciberdelincuencia ruso por $1,600, utiliza módulos PAM para proporcionar acceso SSH persistente con una combinación de contraseña mágica y puerto TCP.

{{< cyber-report severity="High" source="The Hacker News" target="Servidores SSH Linux" >}}

Investigadores de ciberseguridad han descubierto un nuevo backdoor para Linux llamado PamDOORa, anunciado en el foro de ciberdelincuencia ruso Rehub por $1,600 por un actor de amenazas conocido como 'darkworm'. El backdoor está diseñado como un kit de herramientas de post-explotación basado en módulos de autenticación conectables (PAM), que permite acceso SSH persistente mediante una combinación de una contraseña mágica y un puerto TCP específico.

{{< ad-banner >}}

PamDOORa opera interceptando la autenticación SSH a través de módulos PAM maliciosos, permitiendo a los atacantes eludir las credenciales normales y obtener acceso no autorizado. El uso de módulos PAM hace que el backdoor sea sigiloso, ya que se integra en el flujo de autenticación estándar del sistema Linux.

La venta de este tipo de herramientas en foros de ciberdelincuencia resalta la creciente mercantilización de herramientas de ataque sofisticadas. Se recomienda a las organizaciones monitorear patrones inusuales de autenticación SSH y asegurarse de que las configuraciones de PAM se auditen regularmente.

{{< netrunner-insight >}}

Para los analistas de SOC, detectar PamDOORa requiere monitorear conexiones SSH inesperadas en puertos no estándar y correlacionarlas con cambios en los módulos PAM. Los equipos de DevSecOps deben aplicar una gestión estricta de la configuración de PAM y considerar la monitorización de integridad de archivos para /etc/pam.d/ y bibliotecas relacionadas. Este backdoor subraya la importancia de tratar PAM como un límite de seguridad crítico.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html)**
