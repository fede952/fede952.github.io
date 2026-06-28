---
title: "FBI advierte que hackers de inteligencia rusa atacan claves de recuperación de respaldo de Signal"
date: "2026-06-28T09:57:31Z"
original_date: "2026-06-26T19:38:29"
lang: "es"
translationKey: "fbi-warns-russian-intel-hackers-target-signal-backup-recovery-keys"
author: "NewsBot (Validated by Federico Sella)"
description: "Actualización de advertencia de FBI y CISA: el phishing de inteligencia rusa ahora roba claves de recuperación de respaldo de Signal para leer mensajes privados y tomar el control de cuentas."
original_url: "https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html"
source: "The Hacker News"
severity: "High"
target: "usuarios de Signal"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Actualización de advertencia de FBI y CISA: el phishing de inteligencia rusa ahora roba claves de recuperación de respaldo de Signal para leer mensajes privados y tomar el control de cuentas.

{{< cyber-report severity="High" source="The Hacker News" target="usuarios de Signal" >}}

El FBI y CISA han actualizado su advertencia de marzo sobre campañas de phishing de inteligencia rusa dirigidas a cuentas de Signal. Los atacantes han agregado un nuevo paso: ahora engañan a las víctimas para que entreguen su clave de recuperación de respaldo de Signal. Una vez obtenida, la clave permite al atacante restaurar la copia de seguridad de la cuenta, leer el historial de mensajes privados y grupales, y tomar el control total de la cuenta.

{{< ad-banner >}}

La clave sigue siendo válida incluso después del compromiso inicial, lo que permite un acceso persistente. Esta técnica evita la autenticación de dos factores tradicional porque la clave de recuperación está diseñada para la restauración legítima de cuentas. El aviso enfatiza que los usuarios nunca deben compartir su clave de recuperación y deben activar el bloqueo de registro y otras funciones de seguridad.

Las organizaciones deben educar a los usuarios sobre este vector de phishing específico y considerar la implementación de pasos de verificación adicionales para comunicaciones sensibles. La amenaza se atribuye a actores de inteligencia rusa, lo que resalta el contexto geopolítico de la campaña.

{{< netrunner-insight >}}

Este es un ejemplo clásico de ingeniería social dirigida a una función de seguridad. Los analistas de SOC deben monitorear solicitudes inusuales de recuperación de cuentas y educar a los usuarios de que la clave de recuperación de respaldo de Signal nunca debe compartirse. Los equipos de DevSecOps deben considerar integrar autenticación resistente al phishing para comunicaciones críticas.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html)**
