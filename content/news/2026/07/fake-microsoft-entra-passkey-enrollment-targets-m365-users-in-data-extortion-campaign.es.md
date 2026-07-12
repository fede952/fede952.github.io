---
title: "Falsa inscripción de clave de acceso de Entra de Microsoft se dirige a usuarios de M365 en campaña de extorsión de datos"
date: "2026-07-12T09:00:42Z"
original_date: "2026-07-10T10:30:20"
lang: "es"
translationKey: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
slug: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "El actor de amenazas O-UNC-066 utiliza phishing basado en voz para engañar a los usuarios y hacer que inscriban una clave de acceso falsa de Entra, con el objetivo de comprometer cuentas de Microsoft 365 para extorsión de datos."
original_url: "https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html"
source: "The Hacker News"
severity: "High"
target: "Usuarios de Microsoft 365"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

El actor de amenazas O-UNC-066 utiliza phishing basado en voz para engañar a los usuarios y hacer que inscriban una clave de acceso falsa de Entra, con el objetivo de comprometer cuentas de Microsoft 365 para extorsión de datos.

{{< cyber-report severity="High" source="The Hacker News" target="Usuarios de Microsoft 365" >}}

Un actor de amenazas rastreado como O-UNC-066 por Okta ha sido observado realizando ataques de phishing basados en voz dirigidos a usuarios de Microsoft 365 en múltiples sectores. Los atacantes se hacen pasar por solicitudes de seguridad legítimas para engañar a las víctimas y hacer que inscriban una clave de acceso falsa de Entra, otorgando así al adversario acceso no autorizado a sus cuentas.

{{< ad-banner >}}

La campaña utiliza un kit de phishing controlado por panel diseñado específicamente para interceptar el proceso de inscripción de la clave de acceso. Una vez que el atacante obtiene acceso, busca llevar a cabo extorsión de datos, exfiltrando información sensible y exigiendo un rescate. Los ataques resaltan una tendencia creciente de usar canales de voz para eludir las defensas tradicionales de phishing por correo electrónico.

Se recomienda a las organizaciones implementar autenticación multifactor (MFA) con claves de seguridad de hardware y educar a los usuarios sobre cómo verificar cualquier solicitud de seguridad no solicitada a través de canales de comunicación alternativos. Monitorear actividades anómalas de inscripción de claves de acceso puede ayudar a detectar estos ataques de manera temprana.

{{< netrunner-insight >}}

Este ataque subraya la importancia de tratar las solicitudes de seguridad basadas en voz con el mismo escepticismo que los correos de phishing. Los analistas del SOC deben monitorear intentos inusuales de inscripción de claves de acceso y asegurarse de que los procesos de inscripción de MFA requieran verificación fuera de banda. Los equipos de DevSecOps deben considerar implementar políticas de acceso condicional que restrinjan la inscripción de claves de acceso a dispositivos y ubicaciones de confianza.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html)**
