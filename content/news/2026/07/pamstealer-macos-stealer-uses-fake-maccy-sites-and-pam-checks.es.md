---
title: "PamStealer: un ladrón de macOS que usa sitios falsos de Maccy y comprobaciones de PAM"
date: "2026-07-04T09:17:53Z"
original_date: "2026-07-03T08:03:37"
lang: "es"
translationKey: "pamstealer-macos-stealer-uses-fake-maccy-sites-and-pam-checks"
author: "NewsBot (Validated by Federico Sella)"
description: "Jamf Threat Labs descubre PamStealer, un ladrón de información de macOS distribuido a través de sitios falsos de Maccy, que utiliza comprobaciones de PAM para robar contraseñas de inicio de sesión."
original_url: "https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html"
source: "The Hacker News"
severity: "High"
target: "usuarios de macOS"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Jamf Threat Labs descubre PamStealer, un ladrón de información de macOS distribuido a través de sitios falsos de Maccy, que utiliza comprobaciones de PAM para robar contraseñas de inicio de sesión.

{{< cyber-report severity="High" source="The Hacker News" target="usuarios de macOS" >}}

Investigadores de ciberseguridad de Jamf Threat Labs han identificado un nuevo ladrón de información de macOS llamado PamStealer. El malware se distribuye como un archivo AppleScript compilado (.scpt) que se hace pasar por Maccy, un gestor de portapapeles legítimo de código abierto. Emplea una serie de trucos inteligentes para infectar sistemas y extraer datos sensibles, incluyendo contraseñas de inicio de sesión.

{{< ad-banner >}}

PamStealer recibe su nombre por su capacidad de abusar del marco Pluggable Authentication Module (PAM) en macOS. Al interceptar procesos de autenticación, puede capturar credenciales de usuario cuando inician sesión o se autentican para operaciones privilegiadas. El ladrón luego exfiltra los datos robados a servidores controlados por atacantes.

La campaña se basa en sitios web falsos e ingeniería social para engañar a los usuarios y hacer que descarguen el archivo .scpt malicioso. Una vez ejecutado, el malware realiza comprobaciones de PAM para cosechar contraseñas sin levantar sospechas. Las organizaciones con endpoints macOS deben monitorear ejecuciones inusuales de archivos .scpt y anomalías relacionadas con PAM.

{{< netrunner-insight >}}

Para los analistas del SOC, esto resalta la necesidad de monitorear ejecuciones de AppleScript compilado y modificaciones de PAM en endpoints macOS. Los equipos de DevSecOps deben imponer listas blancas de aplicaciones y educar a los usuarios sobre la verificación de fuentes de software, especialmente para gestores de portapapeles. Implementar reglas de detección en endpoints para abusos de PAM puede ayudar a detectar este ladrón tempranamente.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html)**
